using AuthServiceDavivienda.Context;
using AuthServiceDavivienda.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthServiceDavivienda.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserManagmentController : ControllerBase
    {
        private readonly userDbContext _context;

        public UserManagmentController(userDbContext context)
        {
            _context = context;
        }

        [HttpPost("create-user")]
        public object  RegistrarUsuario(Employed empleado)
        {
            try
            {
                empleado.CreatedAt = DateTime.Now;
                empleado.UpdateAt  = DateTime.Now;
                empleado.State = 1;
                empleado.EncryptedPass = Seguridad.EncodeHash(empleado.EncryptedPass);
                empleado.CurrentIp = HttpContext.Connection.RemoteIpAddress.ToString();

                if (_context.Employeds == null)
                {
                    return NotFound(new{ msj = "Modelo no Enccontrado"});
                }

                _context.Employeds.Add(empleado);
                _context.SaveChanges();

            }catch(Exception ex){
                return BadRequest(ex.Message);
            }

            return Ok(new { msj = "Registro Ingresado con Exito" });
        }

        [HttpPost("assign-role")]
        public object AsignarRole(UserRole userRole)
        {
            try
            {
                if (_context.UserRoles == null )
                {
                    return BadRequest(new { msj = "Modelo no Encontrado" });
                }
                if (!_context.Employeds.Any(x => x.Identification.Equals(userRole.UserIdentity))) return NotFound();
                if (!_context.Roles.Any(x => x.Id.Equals(userRole.RoleId))) return NotFound();
                
                userRole.UpdatedAt = DateTime.Now;
                userRole.CreatedAt = DateTime.Now;

                _context.Add(userRole);
                _context.SaveChanges();
            }
            catch(Exception ex)
            {
                return BadRequest(ex.Message);
            }

            return Ok(new
            {
                msj = "Registro Ingresado Correctamente",
                UserRole = userRole
            });

        }

        [HttpGet("Login")]
        public object Login([Required][FromHeader] string Authorization)
        {
            string base64 = Authorization.Replace("Basic ", "");
            var EncodeTextBytes = Convert.FromBase64String(base64);
            var textoPlano = Encoding.UTF8.GetString(EncodeTextBytes);
            var arreglo = textoPlano.Split(":");
            var email = arreglo[0];
            var pass = arreglo[1];

            if (!_context.Employeds.Any(x => x.Email.Equals(email))) return NotFound(new {msj= "Usuario o Contraseña Incorrecta" });
            Employed empleado = _context.Employeds.Where(x => x.Email.Equals(email)).First();

            if (!(empleado.EncryptedPass == Seguridad.EncodeHash(pass))) return Unauthorized(new {msj= "Usuario o Contraseña Incorrecta" });

            string token = Convert.ToBase64String(Guid.NewGuid().ToByteArray()) + DateTime.Now;
            token = Seguridad.EncodeHash( Regex.Replace(token, ' '.ToString(), string.Empty).Trim());
            UserToken userTokenDB = new UserToken();

            try
            {
                if (_context.UserTokens.Any(x => x.UserIdentity.Equals(empleado.Identification)))
                {
                    userTokenDB = _context.UserTokens.Where(x => x.UserIdentity.Equals(empleado.Identification)).First();
                    userTokenDB.CurrentToken = DateTime.Now;
                    userTokenDB.LastToken = userTokenDB.CurrentToken;
                    userTokenDB.UserIdentity = empleado.Identification;
                    _context.Entry(userTokenDB).State = EntityState.Modified;
                    _context.SaveChanges();
                }
                else
                {
                    userTokenDB.CurrentToken = DateTime.Now;
                    userTokenDB.LastToken = DateTime.Now;
                    userTokenDB.HashToken = token;
                    userTokenDB.UserIdentity = empleado.Identification;
                    _context.UserTokens.Add(userTokenDB).State = EntityState.Added;
                    _context.SaveChanges();
                }
            }catch(Exception ex)
            {
                 return Ok(new{
                    msj = ex.Message,
                    userToken = userTokenDB
                 });
            }


            return Ok(new
            {
                msj = "Bienvenido al sistema",
                userToken = userTokenDB
            });

        }

    }
}
