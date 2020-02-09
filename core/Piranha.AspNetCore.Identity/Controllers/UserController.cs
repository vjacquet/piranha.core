/*
 * Copyright (c) 2018-2019 Håkan Edling
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * http://github.com/piranhacms/piranha
 *
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Piranha.AspNetCore.Identity.Data;
using Piranha.AspNetCore.Identity.Models;
using Piranha.Manager;
using Piranha.Manager.Controllers;
using Piranha.Manager.Models;

namespace Piranha.AspNetCore.Identity.Controllers
{
    /// <summary>
    /// Manager controller for managing users accounts.
    /// </summary>
    [Area("Manager")]
    public class UserController : ManagerController
    {
        private readonly string _duplicateUserNameErrorCode;
        private readonly string _duplicateEmailErrorCode;

        private readonly IIdentityService _service;
        private readonly ManagerLocalizer _localizer;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="service">The identity service</param>
        public UserController(IIdentityService service, IdentityErrorDescriber identityErrorDescriber, ManagerLocalizer localizer)
        {
            _service = service;
            _localizer = localizer;

            _duplicateUserNameErrorCode = identityErrorDescriber.DuplicateUserName("").Code;
            _duplicateEmailErrorCode = identityErrorDescriber.DuplicateEmail("").Code;
        }

        /// <summary>
        /// Gets the list view with the currently available users.
        /// </summary>
        [Route("/manager/users")]
        [Authorize(Policy = Permissions.Users)]
        public IActionResult List()
        {
            return View();
        }

        /// <summary>
        /// Gets the list view with the currently available users.
        /// </summary>
        [Route("/manager/users/list")]
        [Authorize(Policy = Permissions.Users)]
        public async Task<UserListModel> Get()
        {
            var model = await _service.GetUserListAsync(HttpContext.RequestAborted);
            return model;
        }

        /// <summary>
        /// Gets the edit view for an existing user.
        /// </summary>
        /// <param name="id">The user id</param>
        [Route("/manager/user/{id?}")]
        [Authorize(Policy = Permissions.UsersEdit)]
        public IActionResult Edit(string id)
        {
            return View((object)id);
        }

        /// <summary>
        /// Gets the edit view for an existing user.
        /// </summary>
        /// <param name="id">The user id</param>
        [Route("/manager/user/edit/{id}")]
        [Authorize(Policy = Permissions.UsersEdit)]
        public async Task<UserEditModel> Get(string id)
        {
            var model = await _service.GetUserByIdAsync(id, HttpContext.RequestAborted);
            return model;
        }

        /// <summary>
        /// Gets the edit view for a new user.
        /// </summary>
        [Route("/manager/user/add")]
        [Authorize(Policy = Permissions.UsersEdit)]
        public UserEditModel Add()
        {
            var model = _service.CreateUser();
            return model;
        }

        /// <summary>
        /// Saves the given user.
        /// </summary>
        /// <param name="model">The user model</param>
        [HttpPost]
        [Route("/manager/user/save")]
        [Authorize(Policy = Permissions.UsersSave)]
        public async Task<IActionResult> Save([FromBody] UserEditModel model)
        {
            if (model.UserName == null)
            {
                return BadRequest(GetErrorMessage(_localizer.Security["The user could not be found."]));
            }

            try
            {
                var userId = model.Id;
                var isNew = string.IsNullOrEmpty(userId);

                if (string.IsNullOrWhiteSpace(model.UserName))
                {
                    return BadRequest(GetErrorMessage(_localizer.General["Username is mandatory."]));
                }

                if (string.IsNullOrWhiteSpace(model.Email))
                {
                    return BadRequest(GetErrorMessage(_localizer.General["Email address is mandatory."]));
                }

                if (!string.IsNullOrWhiteSpace(model.Password) && model.Password != model.PasswordConfirm)
                {
                    return BadRequest(GetErrorMessage(string.Format("{0} {1} - {2}", _localizer.Security["The new passwords does not match."], model.Password, model.PasswordConfirm)));
                }

                if (isNew && string.IsNullOrWhiteSpace(model.Password))
                {
                    return BadRequest(GetErrorMessage(_localizer.Security["Password is mandatory when creating a new user."]));
                }

                var result = await _service.SaveUserAsync(model, HttpContext.RequestAborted);
                if (result.Succeeded)
                {
                    return Ok(await Get(model.Id));
                }
                else if (IsDuplicateUserName(result.Errors))
                {
                    return BadRequest(GetErrorMessage(_localizer.Security["Username is used by another user."]));
                }
                else if (IsDuplicateEmail(result.Errors))
                {
                    return BadRequest(GetErrorMessage(_localizer.Security["Email address is used by another user."]));
                }
                else
                {
                    var errorMessages = new List<string>();
                    errorMessages.AddRange(result.Errors.Select(msg => msg.Description));

                    return BadRequest(GetErrorMessage(_localizer.Security["The user could not be saved."] + "<br/><br/>" + string.Join("<br />", errorMessages)));
                }
            }
            catch (Exception ex)
            {
                return BadRequest(GetErrorMessage(ex.Message));
            }
        }

        bool IsDuplicateUserName(IEnumerable<IdentityError> errors)
        {
            return errors.Any(e => e.Code == _duplicateUserNameErrorCode);
        }

        bool IsDuplicateEmail(IEnumerable<IdentityError> errors)
        {
            return errors.Any(e => e.Code == _duplicateEmailErrorCode);
        }

        /// <summary>
        /// Deletes the user with the given id.
        /// </summary>
        /// <param name="id">The user id</param>
        [Route("/manager/user/delete/{id}")]
        [Authorize(Policy = Permissions.UsersSave)]
        public async Task<IActionResult> Delete(string id)
        {
            var currentUserId = _service.GetUserId(HttpContext.User);
            if (id == currentUserId)
            {
                return BadRequest(GetErrorMessage(_localizer.Security["Can't delete yourself."]));
            }

            if (await _service.DeleteUserAsync(id, HttpContext.RequestAborted))
            {
                return Ok(GetSuccessMessage(_localizer.Security["The user has been deleted."]));
            }

            return NotFound(GetErrorMessage(_localizer.Security["The user could not be found."]));
        }

        private AliasListModel GetSuccessMessage(string message)
        {
            return GetMessage(message, StatusMessage.Success);
        }

        private AliasListModel GetErrorMessage(string errorMessage)
        {
            return GetMessage(!string.IsNullOrWhiteSpace(errorMessage) ? errorMessage : _localizer.General["An error occurred"], StatusMessage.Error);
        }

        private AliasListModel GetMessage(string message, string type)
        {
            var result = new AliasListModel();
            result.Status = new StatusMessage
            {
                Type = type,
                Body = message
            };
            return result;
        }
    }
}