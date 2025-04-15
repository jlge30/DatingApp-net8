using System;
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(DataContext context) : BaseApiController
{
    [HttpPost("register")] // account/register
    public async Task<ActionResult<AppUser>> Register(RegisterDto registerDto)
    {
        if (await UserExist(registerDto.UserName)) return BadRequest("User name is taken");

        using var hmac = new HMACSHA3_512();

        var user = new AppUser
         {
            UserName = registerDto.UserName.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };
       

        context.Users.Add(user);
        context.SaveChangesAsync();

        return user; 

    }

    private async Task<bool> UserExist(string username)
    {
        IEnumerable<AppUser> list = await context.Users.ToListAsync();
         return list.Any( x => x.UserName.ToLower().Equals(username.ToLower()));

    }

}
