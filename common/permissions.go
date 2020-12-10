package common

// Permission is a bitmask representing authorized privileges for user
// or authorization token; the permissions namespace has been split into
// partitions for readability: 2^24 permissions
type Permission uint32

const (
	// Authenticate permission
	Authenticate Permission = 0x1

	// ReadResources generic permission
	ReadResources Permission = 0x2

	// CreateResource generic permission
	CreateResource Permission = 0x4

	// UpdateResource generic permission
	UpdateResource Permission = 0x8

	// DeleteResource generic permission
	DeleteResource Permission = 0x10

	// GrantResourceAuthorization generic permission
	GrantResourceAuthorization Permission = 0x20

	// RevokeResourceAuthorization generic permission
	RevokeResourceAuthorization Permission = 0x40

	// Publish permission
	Publish Permission = 0x80

	// Subscribe permission
	Subscribe Permission = 0x100

	// Reserved permission - placeholder for future use
	Reserved Permission = 0x200

	// Ident-specific permissions begin at 2^10

	// ListApplications permission
	ListApplications Permission = 0x400

	// CreateApplication permission
	CreateApplication Permission = 0x800

	// UpdateApplication permission
	UpdateApplication Permission = 0x1000

	// DeleteApplication permission
	DeleteApplication Permission = 0x2000

	// ListApplicationTokens permission
	// ListApplicationTokens Permission = 0x4000

	// CreateApplicationToken permission
	// CreateApplicationToken Permission = 0x8000

	// DeleteApplicationToken permission
	// DeleteApplicationToken Permission = 0x10000

	// Privileged permissions begin at 2^20

	// ListUsers permission for administrative listing of users
	ListUsers Permission = 0x100000

	// CreateUser permission for administrative creation of new users
	CreateUser Permission = 0x200000

	// UpdateUser permission for administrative updates to existing users
	UpdateUser Permission = 0x400000

	// DeleteUser permission for administratively removing users
	DeleteUser Permission = 0x800000

	// ListTokens permission for administration to retrieve a list of all legacy auth tokens
	ListTokens Permission = 0x1000000

	// CreateToken permission for administratively creating new legacy auth tokens
	CreateToken Permission = 0x2000000

	// DeleteToken permission for administratively revoking legacy auth tokens
	DeleteToken Permission = 0x4000000

	// Sudo permission
	Sudo Permission = 0x20000000
)

// DefaultUserPermission is the default mask to use if permissions are not explicitly set upon user creation
const DefaultUserPermission Permission = Authenticate | ReadResources | CreateResource | UpdateResource | DeleteResource | Publish | Subscribe

// DefaultApplicationResourcePermission is the default mask to use for an application subresource if permissions are not explicitly set upon application token creation
const DefaultApplicationResourcePermission Permission = ReadResources | CreateResource | UpdateResource | DeleteResource | GrantResourceAuthorization | RevokeResourceAuthorization | Publish | Subscribe

// DefaultApplicationOrganizationPermission is the default mask to use for an application organization if permissions are not explicitly set upon application organization creation
const DefaultApplicationOrganizationPermission Permission = Publish | Subscribe | DefaultApplicationResourcePermission

// DefaultApplicationUserResourcePermission is the default mask to use for an application subresource if permissions are not explicitly set upon application token creation
const DefaultApplicationUserResourcePermission Permission = ReadResources | CreateResource | UpdateResource | DeleteResource | GrantResourceAuthorization | RevokeResourceAuthorization | Publish | Subscribe

// DefaultAuth0RequestPermission is the ephemeral permission mask to apply to Auth0 requests
const DefaultAuth0RequestPermission = ListUsers | CreateUser

// DefaultOrganizationTokenPermission is the default mask to use for an organization if permissions are not explicitly set upon organization token creation
const DefaultOrganizationTokenPermission Permission = ReadResources | CreateResource | UpdateResource | DeleteResource

// DefaultOrganizationUserPermission is the default mask to use for an organization user if permissions are not explicitly set upon organization user creation
const DefaultOrganizationUserPermission Permission = Publish | Subscribe | ReadResources

// DefaultSudoerPermission is the default mask to use when a new sudoer is created
const DefaultSudoerPermission = DefaultUserPermission | Sudo

// set updates the mask with the given permissions; package private
func (p Permission) set(flags Permission) Permission {
	return p | flags
}

// Has checks for the presence of the given permissions
func (p Permission) Has(flags Permission) bool {
	return p&flags != 0
}
