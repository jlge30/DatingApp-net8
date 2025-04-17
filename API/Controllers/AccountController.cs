using System;
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(DataContext context, ITokenService tokenService) : BaseApiController
{
    [HttpPost("register")] // account/register
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        if (await UserExist(registerDto.UserName)) return BadRequest("User name is taken");

        using var hmac = new HMACSHA512();

        var user = new AppUser
         {
            UserName = registerDto.UserName.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };
       

        context.Users.Add(user);
        context.SaveChangesAsync();

        return new UserDto
        {
            UserName = user.UserName,
            Token = tokenService.CreateToken(user)
        };

    }

    [HttpPost("login")] // account/login
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
    {
        var user = await context.Users.FirstOrDefaultAsync(x=>
        x.UserName == loginDto.Username.ToLower());

        if (user == null) return Unauthorized("Invalid username or password");

        using var hmac = new HMACSHA512(user.PasswordSalt);

        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

        for (int i = 0; i < computedHash.Length; i++)
        {
            if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");

        }
        return new UserDto
        {
            UserName = user.UserName,
            Token = tokenService.CreateToken(user)
        };

    }

    private async Task<bool> UserExist(string username)
    {
        IEnumerable<AppUser> list = await context.Users.ToListAsync();
         return list.Any( x => x.UserName.ToLower().Equals(username.ToLower()));

    }

}
