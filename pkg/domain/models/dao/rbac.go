package dao

// Role is a named bundle of permissions assignable to users.
type Role struct {
	ID          int64        `gorm:"column:id;primaryKey;autoIncrement"`
	Name        string       `gorm:"column:name;uniqueIndex;not null"`
	Description string       `gorm:"column:description"`
	Permissions []Permission `gorm:"many2many:role_permissions;joinForeignKey:role_id;joinReferences:permission_id"`
}

func (Role) TableName() string { return "roles" }

// Permission is a granular action, e.g. "user.read", "user.disable".
type Permission struct {
	ID          int64  `gorm:"column:id;primaryKey;autoIncrement"`
	Name        string `gorm:"column:name;uniqueIndex;not null"`
	Description string `gorm:"column:description"`
}

func (Permission) TableName() string { return "permissions" }

// RolePermission is the role↔permission join row (declared so AutoMigrate names
// the table and columns predictably).
type RolePermission struct {
	RoleID       int64 `gorm:"column:role_id;primaryKey"`
	PermissionID int64 `gorm:"column:permission_id;primaryKey"`
}

func (RolePermission) TableName() string { return "role_permissions" }

// UserRole is the user↔role join row.
type UserRole struct {
	UserID int64 `gorm:"column:user_id;primaryKey"`
	RoleID int64 `gorm:"column:role_id;primaryKey"`
}

func (UserRole) TableName() string { return "user_roles" }
