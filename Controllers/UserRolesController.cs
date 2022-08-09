using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AuthServiceDavivienda.Context;
using AuthServiceDavivienda.Models;
using System.ComponentModel.DataAnnotations;

namespace AuthServiceDavivienda.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserRolesController : ControllerBase
    {
        private readonly userDbContext _context;

        public UserRolesController(userDbContext context)
        {
            _context = context;
        }

        // GET: api/UserRoles
        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserRole>>> GetUserRoles([Required][FromHeader] String Authorization)
        {
          if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });
          
          if (_context.UserRoles == null)
          {
              return NotFound();
          }
            return await _context.UserRoles.ToListAsync();
        }

        // GET: api/UserRoles/5
        [HttpGet("{id}")]
        public async Task<ActionResult<UserRole>> GetUserRole([Required][FromHeader] String Authorization,int id)
        {
          if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });
          if (_context.UserRoles == null)
          {
              return NotFound();
          }
            var userRole = await _context.UserRoles.FindAsync(id);

            if (userRole == null)
            {
                return NotFound();
            }

            return userRole;
        }

        // PUT: api/UserRoles/5
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{id}")]
        public async Task<IActionResult> PutUserRole([Required][FromHeader] String Authorization,int id, UserRole userRole)
        {
            if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });
            if (id != userRole.Id)
            {
                return BadRequest();
            }

            _context.Entry(userRole).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserRoleExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // POST: api/UserRoles
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<UserRole>> PostUserRole([Required][FromHeader] String Authorization, UserRole userRole)
        {
          if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });
          if (_context.UserRoles == null)
          {
              return Problem("Entity set 'userDbContext.UserRoles'  is null.");
          }
            _context.UserRoles.Add(userRole);
            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                if (UserRoleExists(userRole.Id))
                {
                    return Conflict();
                }
                else
                {
                    throw;
                }
            }

            return CreatedAtAction("GetUserRole", new { id = userRole.Id }, userRole);
        }

        // DELETE: api/UserRoles/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUserRole([Required][FromHeader] String Authorization, int id)
        {
            if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });
            if (_context.UserRoles == null)
            {
                return NotFound();
            }
            var userRole = await _context.UserRoles.FindAsync(id);
            if (userRole == null)
            {
                return NotFound();
            }

            _context.UserRoles.Remove(userRole);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private bool UserRoleExists(int id)
        {
            return (_context.UserRoles?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
