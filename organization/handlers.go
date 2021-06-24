package organization

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/ident/token"
	"github.com/provideplatform/ident/user"

	vault "github.com/provideplatform/provide-go/api/vault"
	provide "github.com/provideplatform/provide-go/common"
)

// InstallOrganizationAPI installs handlers using the given gin Engine
func InstallOrganizationAPI(r *gin.Engine) {
	r.GET("/api/v1/organizations", organizationsListHandler)
	r.GET("/api/v1/organizations/:id", organizationDetailsHandler)
	r.POST("/api/v1/organizations", createOrganizationHandler)
	r.PUT("/api/v1/organizations/:id", updateOrganizationHandler)
	r.DELETE("/api/v1/organizations/:id", deleteOrganizationHandler)
}

// InstallOrganizationUsersAPI installs the handlers using the given gin Engine
func InstallOrganizationUsersAPI(r *gin.Engine) {
	r.GET("/api/v1/organizations/:id/users", organizationUsersListHandler)
	r.POST("/api/v1/organizations/:id/users", createOrganizationUserHandler)
	r.PUT("/api/v1/organizations/:id/users/:userId", updateOrganizationUserHandler)
	r.DELETE("/api/v1/organizations/:id/users/:userId", deleteOrganizationUserHandler)

	r.GET("/api/v1/organizations/:id/invitations", organizationInvitationsListHandler)
}

// InstallOrganizationVaultsAPI installs the handlers using the given gin Engine
func InstallOrganizationVaultsAPI(r *gin.Engine) {
	r.GET("/api/v1/organizations/:id/vaults", organizationVaultsListHandler)

	r.GET("/api/v1/organizations/:id/vaults/:vaultId/keys", organizationVaultKeysListHandler)
	r.POST("/api/v1/organizations/:id/vaults/:vaultId/keys", createOrganizationVaultKeyHandler)
	// r.DELETE("/api/v1/organizations/:id/vaults/:vaultId/keys/:keyId", deleteOrganizationVaultKeyHandler)
	r.POST("/api/v1/organizations/:id/vaults/:vaultId/keys/:keyId/sign", organizationVaultKeySignHandler)
	r.POST("/api/v1/organizations/:id/vaults/:vaultId/keys/:keyId/verify", organizationVaultKeyVerifyHandler)

	r.GET("/api/v1/organizations/:id/vaults/:vaultId/secrets", organizationVaultSecretsListHandler)
	// r.POST("/api/v1/organizations/:id/vaults/:vaultId/secrets", createOrganizationVaultSecretHandler)
	// r.DELETE("/api/v1/organizations/:id/vaults/:vaultId/secrets/:secretId", deleteOrganizationVaultSecretHandler)
}

func resolveOrganization(db *gorm.DB, orgID, appID, userID *uuid.UUID) *gorm.DB {
	query := db.Where("organizations.enabled = true")
	if appID != nil {
		query = db.Joins("JOIN applications_organizations as ao ON ao.organization_id = organizations.id").Where("ao.application_id = ?", appID)
	}
	if orgID != nil {
		if appID != nil {
			query = query.Where("ao.organization_id = ?", orgID)
		} else {
			query = query.Where("organizations.id = ?", orgID)
		}
	}
	if userID != nil {
		query = query.Joins("JOIN organizations_users as ou ON ou.organization_id = organizations.id").Where("ou.user_id = ?", userID)
	}
	return query.Order("organizations.created_at DESC").Group("organizations.id")
}

func resolveOrganizationUsers(db *gorm.DB, orgID uuid.UUID, appID *uuid.UUID) *gorm.DB {
	query := db.Select("users.id, users.created_at, users.first_name, users.last_name, ou.permissions as permissions")
	query = query.Joins("JOIN organizations_users as ou ON ou.user_id = users.id").Where("ou.organization_id = ?", orgID)
	if appID != nil {
		query = query.Joins("JOIN applications_organizations as ao ON ao.organization_id = ou.organization_id").Where("ao.application_id = ?", appID)
	}
	return query
}

func organizationsListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	applicationID := bearer.ApplicationID
	userID := bearer.UserID

	if (userID == nil || *userID == uuid.Nil) && (applicationID == nil || *applicationID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var orgs []*Organization

	db := dbconf.DatabaseConnection()
	query := resolveOrganization(db, nil, applicationID, userID)
	provide.Paginate(c, query, &Organization{}).Find(&orgs)
	for _, org := range orgs {
		org.Enrich(db, nil)
	}
	provide.Render(orgs, 200, c)
}

func organizationDetailsHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	orgID := bearer.OrganizationID

	if (userID == nil || *userID == uuid.Nil) && (orgID == nil || *orgID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	if orgID != nil && orgID.String() != c.Param("id") {
		provide.RenderError("forbidden", 403, c)
		return
	}

	// if we don't have an org bearer token, pull the org id from the params
	// the resolveOrganization will ensure that the bearer token user is
	// associated with that org
	if orgID == nil {
		organizationID, err := uuid.FromString(c.Param("id"))
		if err != nil {
			provide.RenderError("bad request", 400, c)
			return
		}
		orgID = &organizationID
	}

	db := dbconf.DatabaseConnection()
	org := &Organization{}
	resolveOrganization(db, orgID, nil, userID).Find(&org)

	if org == nil || org.ID == uuid.Nil {
		provide.RenderError("organization not found", 404, c)
		return
	}

	org.Enrich(db, nil)
	provide.Render(org, 200, c)
}

func createOrganizationHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID

	if userID == nil || *userID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	org := &Organization{}
	err = json.Unmarshal(buf, &org)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}
	org.UserID = userID

	var invite *user.Invite
	var permissions common.Permission

	if invitationToken, invitationTokenOk := params["invitation_token"].(string); invitationTokenOk {
		invite, err = user.ParseInvite(invitationToken, false)
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}

		if invite.OrganizationID != nil {
			provide.RenderError("invitation contained specific organization_id", 400, c)
			return
		}

		if invite.UserID != nil && userID != nil && invite.UserID.String() != userID.String() {
			provide.RenderError("invitation user_id did not match authorized user", 403, c)
			return
		}

		if invite.Permissions != nil {
			permissions = *invite.Permissions
		} else {
			permissions = common.DefaultApplicationResourcePermission
		}
	}

	if _, permissionsOk := params["permissions"]; permissionsOk {
		provide.RenderError("unable to assert arbitrary organization permissions", 403, c)
		return
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	success := org.Create(tx)
	if success && invite != nil {
		if invite.ApplicationID != nil {
			success = org.addApplicationAssociation(tx, *invite.ApplicationID, permissions)
		}

		if success {
			success = invite.Token.IsRevoked() || invite.Token.Revoke(tx)
			if success {
				invite.InvalidateCache()
			}
		}
	}

	if success {
		tx.Commit()
		provide.Render(org, 201, c)
	} else {
		tx.Rollback()
		obj := map[string]interface{}{}
		obj["errors"] = org.Errors
		provide.Render(obj, 422, c)
	}
}

func updateOrganizationHandler(c *gin.Context) {
	bearer := token.InContext(c)
	if bearer == nil || (bearer.UserID == nil || *bearer.UserID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	org := &Organization{}
	dbconf.DatabaseConnection().Where("id = ?", c.Param("id")).Find(&org)
	if org.ID == uuid.Nil {
		provide.RenderError("org not found", 404, c)
		return
	}

	if bearer.UserID != nil && bearer.UserID.String() != org.UserID.String() { // FIXME-- this should be more than just org.UserID
		provide.RenderError("forbidden", 403, c)
		return
	}

	err = json.Unmarshal(buf, org)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if org.Update() {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = org.Errors
		provide.Render(obj, 422, c)
	}
}

func deleteOrganizationHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func organizationInvitationsListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	applicationID := bearer.ApplicationID
	organizationID := bearer.OrganizationID

	if (userID == nil || *userID == uuid.Nil) && (applicationID == nil || *applicationID == uuid.Nil) && (organizationID == nil || *organizationID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	orgID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if organizationID != nil && organizationID.String() != orgID.String() {
		provide.RenderError(err.Error(), 403, c)
		return
	}

	org := &Organization{}
	query := dbconf.DatabaseConnection()
	resolveOrganization(query, &orgID, applicationID, userID).Find(&org)

	if org == nil || org.ID == uuid.Nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	invitations := org.pendingInvitations() // FIXME-- paginate the in-memory invitations list within redis
	invitedUsers := make([]*user.User, 0)
	for _, invite := range invitations {
		usr := &user.User{
			FirstName: invite.FirstName,
			LastName:  invite.LastName,
			Email:     invite.Email,
		}
		if invite.Permissions != nil {
			usr.Permissions = *invite.Permissions
		}
		invitedUsers = append(invitedUsers, usr)
	}
	provide.Render(invitedUsers, 200, c)
}

func organizationUsersListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	bearerUserID := bearer.UserID
	bearerOrganizationID := bearer.OrganizationID
	bearerApplicationID := bearer.ApplicationID

	listRightsGranted := false

	organizationID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	db := dbconf.DatabaseConnection()

	// check if organization exists
	org := &Organization{}
	resolveOrganization(db, &organizationID, nil, nil).Find(&org)
	if org == nil || org.ID == uuid.Nil {
		provide.RenderError("organization not found", 404, c)
		return
	}

	// bearer Application token even if org is in app, must have ReadResources bearer permission
	if bearerApplicationID != nil {
		resolveOrganization(db, &organizationID, bearerApplicationID, nil).Find(&org)
		if org == nil || org.ID == uuid.Nil {
			provide.RenderError("unauthorized - org not in app", 401, c)
			return
		}

		// check for read resources permision
		// HACK commented until the token setup is completed
		// if !bearer.HasPermission(common.ReadResources) {
		// 	provide.RenderError("unauthorized - insufficient permissions", 401, c)
		// 	return
		// }

		listRightsGranted = true
	}

	// bearer Organization token must still have ReadResources bearer permission
	if bearerOrganizationID != nil && (*bearer.OrganizationID == organizationID) && !listRightsGranted {
		resolveOrganization(db, &organizationID, nil, nil).Find(&org)
		if org == nil || org.ID == uuid.Nil {
			provide.RenderError("unauthorized - org not resolved", 401, c)
			return
		}

		// check for read resources permision
		// HACK commented until the token setup is completed
		// if !bearer.HasPermission(common.ReadResources) {
		// 	provide.RenderError("unauthorized - insufficient permissions", 401, c)
		// 	return
		// }
		listRightsGranted = true
	}

	// bearer user id must be user in org and have ReadResources permission
	if bearerUserID != nil && !listRightsGranted {
		// check if user is in org
		resolveOrganization(db, &organizationID, nil, bearerUserID).Find(&org)
		if org == nil || org.ID == uuid.Nil {
			provide.RenderError("unauthorized - user not in org", 401, c)
			return
		}

		// check for read resources permision
		// HACK commented until the token setup is completed
		// if !bearer.HasPermission(common.ReadResources) {
		// 	provide.RenderError("unauthorized - insufficient permissions", 401, c)
		// 	return
		// }
		listRightsGranted = true
	}

	if listRightsGranted {
		usersQuery := resolveOrganizationUsers(db, organizationID, bearerApplicationID).Order("users.created_at ASC")

		var users []*user.User
		provide.Paginate(c, usersQuery, &user.User{}).Find(&users)
		for _, usr := range users {
			usr.Enrich()
		}
		provide.Render(users, 200, c)
	}

	if !listRightsGranted {
		provide.RenderError("unauthorized", 401, c)
		return
	}

}

func createOrganizationUserHandler(c *gin.Context) {
	bearer := token.InContext(c)
	bearerUserID := bearer.UserID
	// bearerOrganizationID := bearer.OrganizationID (CHECKME - can an org token invite a user? - I'm assuming no for now)
	// bearerApplicationID := bearer.ApplicationID   (CHECKME - can an app token invite a user? - I'm assuming no for now)

	// createRightsGranted := false without the ability for org or app to grant, we don't need this

	// get the organization id
	organizationID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	// get the user id of the user to be added to the org
	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	userID := uuid.Nil
	if userIDStr, userIDStrOk := params["user_id"].(string); userIDStrOk {
		err := err
		userID, err = uuid.FromString(userIDStr)
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
	}

	db := dbconf.DatabaseConnection()

	// check if organization exists
	org := &Organization{}
	resolveOrganization(db, &organizationID, nil, nil).Find(&org)
	if org == nil || org.ID == uuid.Nil {
		provide.RenderError("organization not found", 404, c)
		return
	}

	// check if the user exists
	usr := &user.User{}
	db.Where("id = ?", userID).Find(&usr)
	if usr == nil || usr.ID == uuid.Nil {
		provide.RenderError("user not found", 404, c)
		return
	}

	// CHECKME this all left as is (mostly, I assume the bearerUserID is the inviter, and the invite.UserID is the invitee)
	// - could be dragons
	var invite *user.Invite
	var permissions common.Permission

	if invitationToken, invitationTokenOk := params["invitation_token"].(string); invitationTokenOk {
		invite, err = user.ParseInvite(invitationToken, false)
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}

		if invite.OrganizationID == nil {
			provide.RenderError("invitation did not specify organization_id", 403, c)
			return
		}

		if invite.OrganizationID.String() != organizationID.String() {
			provide.RenderError("invitation organization_id did not match authorized organization", 403, c)
			return
		}

		if invite.UserID != nil && bearerUserID != nil && invite.UserID.String() != bearerUserID.String() {
			provide.RenderError("invitation user_id did not match authorized user", 403, c)
			return
		}
	}

	orgPermissions, permissionsOk := params["permissions"].(common.Permission)
	if permissionsOk && !bearer.HasAnyExtendedPermission(organizationResourceKey, common.CreateResource, common.GrantResourceAuthorization) {
		provide.RenderError("unable to assert arbitrary organization user permissions", 403, c)
		return
	} else if permissionsOk {
		permissions = orgPermissions
	} else if invite != nil && invite.Permissions != nil {
		permissions = *invite.Permissions
	} else {
		permissions = common.DefaultOrganizationUserPermission //CHECKME - easy to miss this one!
	}

	tx := db.Begin()

	success := org.addUser(tx, *usr, permissions)
	if success && invite != nil {
		success = invite.Token.IsRevoked() || invite.Token.Revoke(tx)
		if success {
			invite.InvalidateCache()
		}
	}

	if success {
		tx.Commit()
		provide.Render(nil, 204, c)
	} else {
		tx.Rollback()
		obj := map[string]interface{}{}
		obj["errors"] = org.Errors
		provide.Render(obj, 422, c)
	}
}

func updateOrganizationUserHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

// deleteOrganizationUserHandler deletes an organization user
func deleteOrganizationUserHandler(c *gin.Context) {
	bearer := token.InContext(c)

	// pull the information from the bearer token
	bearerApplicationID := bearer.ApplicationID
	bearerOrganizationID := bearer.OrganizationID
	bearerUserID := bearer.UserID

	// default is not to delete
	deleteRightsGranted := false

	// this action can be completed under the following conditions:

	// First Priority: 	The bearer token contains an ApplicationID which the params.OrganizationID is linked to in the applications_organizations table
	// Permissions?: 		No user permissions checks required - Application token trumps all
	// Result: 					PROCEED WITH DELETE

	// Second Priority: The bearer token contains an OrganizationID corresponding to the params.OrganizationID
	// Permissions?:		No user permissions checks required - Organization token allows all organization operations
	// Result: 					PROCEED WITH DELETE

	// Third Priority: 	The bearer token contains a UserID corresponding to the params.UserID
	// Third Priority: 	AND the UserID has the DeleteX Permission in the organizations_users table
	// Result:					PROCEED WITH DELETE
	// Question: 				if the user has specific DeleteResource permissions in the organizations_users table, can they delete another user, or themselves? YES

	// todo at some point: allow the user in the organization table to reset up a user, or something

	// ensure we have the required parameters
	organizationID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	userID, err := uuid.FromString(c.Param("userId"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	db := dbconf.DatabaseConnection()

	// check if organization exists
	org := &Organization{}
	resolveOrganization(db, &organizationID, nil, nil).Find(&org)
	if org == nil || org.ID == uuid.Nil {
		provide.RenderError("organization not found", 404, c)
		return
	}

	// check if user exists
	usr := &user.User{}
	db.Where("id = ?", userID).Find(&usr)
	if usr == nil || usr.ID == uuid.Nil {
		provide.RenderError("user not found", 404, c)
		return
	}

	// check if we have a bearer Application token...
	if bearerApplicationID != nil {
		// check application_organization table to check if the organizationID belongs to the bearerApplicationID
		// if it does, check that the userID is in the organizationID (organization_users table)
		// if the userID is in the organizationID,
		// AND the bearer token has the DeleteResource permission deleteRightsGranted := true
		resolveOrganization(db, &organizationID, bearerApplicationID, &userID).Find(&org)
		if org == nil || org.ID == uuid.Nil {
			provide.RenderError("unauthorized - org not in app", 401, c)
			return
		}

		// // check for delete resource permision
		// HACK remove until permissions tidied up
		// if !bearer.HasPermission(common.DeleteResource) {
		// 	provide.RenderError("unauthorized - insufficient permissions", 401, c)
		// 	return
		// }
		deleteRightsGranted = true
	}

	// check if we have a bearer Organization token...
	if bearerOrganizationID != nil && (*bearer.OrganizationID == organizationID) && !deleteRightsGranted {
		// check that the userID is in the organizationID (organization_users table)
		// if the userID is in the organizationID
		// AND the bearer token has the DeleteResource permission deleteRightsGranted := true
		resolveOrganization(db, &organizationID, nil, &userID).Find(&org)
		if org == nil || org.ID == uuid.Nil {
			provide.RenderError("unauthorized - user not in org", 401, c)
			return
		}

		// check for delete resource permision
		// HACK remove until permissions tidied up
		// if !bearer.HasPermission(common.DeleteResource) {
		// 	provide.RenderError("unauthorized - insufficient permissions", 401, c)
		// 	return
		// }

		deleteRightsGranted = true
	}

	// check if we have a bearer User token for the userID
	if bearerUserID != nil && (*bearerUserID == userID) && !deleteRightsGranted {
		// 2. check that the bearerUserID is in the organizationID (organization_users table)
		resolveOrganization(db, &organizationID, nil, bearerUserID).Find(&org)
		if org == nil || org.ID == uuid.Nil {
			provide.RenderError("unauthorized - bearer user not in org", 401, c)
			return
		}

		// check for delete resource permision
		// HACK remove until permissions tidied up
		// if !bearer.HasPermission(common.DeleteResource) {
		// 	provide.RenderError("unauthorized - insufficient permissions", 401, c)
		// 	return
		// }

		deleteRightsGranted = true
	}

	// check that the bearer User token is for the organizing user
	if bearerUserID != nil && (*bearerUserID != userID) && !deleteRightsGranted {
		// the bearerToken user is performing an action on another user
		// TODO check that both bearerUserId and userID are in the same org
		// TODO check permissions for DeleteResource permission
		// if OK, deleteRightsGranted := true

		// check the bearer user is in the organization
		resolveOrganization(db, &organizationID, nil, bearerUserID).Find(&org)
		if org == nil || org.ID == uuid.Nil {
			provide.RenderError("unauthorized - bearer user not in org", 401, c)
			return
		}

		//check the user is also in the organization
		resolveOrganization(db, &organizationID, nil, &userID).Find(&org)
		if org == nil || org.ID == uuid.Nil {
			provide.RenderError("unauthorized - user not in org", 401, c)
			return
		}

		// check for delete resource permision
		// HACK remove until permissions tidied up
		// if !bearer.HasPermission(common.DeleteResource) {
		// 	provide.RenderError("unauthorized - insufficient permissions", 401, c)
		// 	return
		// }

		deleteRightsGranted = true
	}

	if deleteRightsGranted {
		if org.removeUser(db, usr) {
			provide.Render(nil, 204, c)
		} else {
			obj := map[string]interface{}{}
			obj["errors"] = org.Errors
			provide.Render(obj, 422, c)
		}
	}

	if !deleteRightsGranted {
		provide.RenderError("unauthorized", 401, c)
		return
	}
}

func organizationVaultsListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	applicationID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (applicationID == nil || *applicationID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	vaults, err := vault.ListVaults(*bearer.Token, map[string]interface{}{})
	if err != nil {
		provide.RenderError(err.Error(), 500, c) // FIXME -- should this be passed via err or remain 500?
		return
	}
	provide.Render(vaults, 200, c)
}

func organizationVaultKeysListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	applicationID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (applicationID == nil || *applicationID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	keys, err := vault.ListKeys(*bearer.Token, c.Param("vaultId"), map[string]interface{}{})
	if err != nil {
		provide.RenderError(err.Error(), 500, c) // FIXME -- should this be passed via err or remain 500?
		return
	}
	provide.Render(keys, 200, c)
}

func createOrganizationVaultKeyHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	applicationID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (applicationID == nil || *applicationID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	key, err := vault.CreateKey(*bearer.Token, c.Param("vaultId"), map[string]interface{}{})
	if err != nil {
		provide.RenderError(err.Error(), 500, c) // FIXME -- should this be passed via err or remain 500?
		return
	}
	provide.Render(key, 201, c)
}

func organizationVaultKeySignHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	applicationID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (applicationID == nil || *applicationID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	resp, err := vault.SignMessage(*bearer.Token, c.Param("vaultId"), c.Param("keyId"), params["message"].(string), map[string]interface{}{})
	if err != nil {
		provide.RenderError(err.Error(), 500, c) // FIXME -- should this be passed via err or remain 500?
		return
	}
	provide.Render(resp, 200, c)
}

func organizationVaultKeyVerifyHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	applicationID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (applicationID == nil || *applicationID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := map[string]interface{}{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	msg := params["message"].(string)
	sig := params["signature"].(string)

	resp, err := vault.VerifySignature(*bearer.Token, c.Param("vaultId"), c.Param("keyId"), msg, sig, map[string]interface{}{})
	if err != nil {
		provide.RenderError(err.Error(), 500, c) // FIXME -- should this be passed via err or remain 500?
		return
	}
	provide.Render(resp, 200, c)
}

func organizationVaultSecretsListHandler(c *gin.Context) {
	bearer := token.InContext(c)
	userID := bearer.UserID
	applicationID := bearer.ApplicationID

	if (userID == nil || *userID == uuid.Nil) && (applicationID == nil || *applicationID == uuid.Nil) {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	secrets, err := vault.ListSecrets(*bearer.Token, c.Param("vaultId"), map[string]interface{}{})
	if err != nil {
		provide.RenderError(err.Error(), 500, c) // FIXME -- should this be passed via err or remain 500?
		return
	}
	provide.Render(secrets, 200, c)
}
