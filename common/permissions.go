package common

// Permission is a bitmask representing authorized privileges for user
// or authorization token; the permissions namespace has been split into
// partitions for readability: 2^24 permissions
type Permission uint32

const (
	// AppPermission1 permission
	AppPermission1 Permission = 0x1

	// AppPermission2 permission
	AppPermission2 Permission = 0x2

	// AppPermission3 permission
	AppPermission3 Permission = 0x4

	// AppPermission4 permission
	AppPermission4 Permission = 0x8

	// AppPermission5 permission
	AppPermission5 Permission = 0x10

	// AppPermission6 permission
	AppPermission6 Permission = 0x12

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
const DefaultUserPermission Permission = 0x0

// DefaultAuth0RequestPermission is the ephemeral permission mask to apply to Auth0 requests
const DefaultAuth0RequestPermission = ListUsers | CreateUser

// DefaultSudoerPermission is the default mask to use when a new sudoer is created
const DefaultSudoerPermission = Sudo

// set updates the mask with the given permissions; package private
func (p Permission) set(flags Permission) Permission {
	return p | flags
}

// Has checks for the presence of the given permissions
func (p Permission) Has(flags Permission) bool {
	return p&flags != 0
}
