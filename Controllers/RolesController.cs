﻿using System;
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
    public class RolesController : ControllerBase
    {
        private readonly userDbContext _context;

        public RolesController(userDbContext context)
        {
            _context = context;
        }

        // GET: api/Roles
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Role>>> GetRoles([Required][FromHeader] string Authorization)
        {
            if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });
          if (_context.Roles == null)
          {
              return NotFound();
          }
            return await _context.Roles.ToListAsync();
        }

        // GET: api/Roles/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Role>> GetRole([Required][FromHeader] string Authorization, int id)
        {
            if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });
            if (_context.Roles == null)
          {
              return NotFound();
          }
            var role = await _context.Roles.FindAsync(id);

            if (role == null)
            {
                return NotFound();
            }

            return role;
        }

        // PUT: api/Roles/5
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPut("{id}")]
        public async Task<IActionResult> PutRole([Required][FromHeader] string Authorization, int id, Role role)
        {
            if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });
            if (id != role.Id)
            {
                return BadRequest();
            }

            _context.Entry(role).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!RoleExists(id))
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

        // POST: api/Roles
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        public async Task<ActionResult<Role>> PostRole([Required][FromHeader] string Authorization, Role role)
        {
            if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });

            if (_context.Roles == null)
            {
              return Problem("Entity set 'userDbContext.Roles'  is null.");
            }
            _context.Roles.Add(role);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetRole", new { id = role.Id }, role);
        }

        // DELETE: api/Roles/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole([Required][FromHeader] string Authorization,int id)
        {
            if (!_context.UserTokens.Any(x => x.HashToken.Equals(Authorization))) return Unauthorized(new { msj = "Usuario No Autorizado" });

            if (_context.Roles == null)
            {
                return NotFound();
            }
            var role = await _context.Roles.FindAsync(id);
            if (role == null)
            {
                return NotFound();
            }

            _context.Roles.Remove(role);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private bool RoleExists(int id)
        {
            return (_context.Roles?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
