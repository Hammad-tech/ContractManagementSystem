# Default Login Credentials

When you first run the application, the following user accounts are automatically created:

## Admin Account
- **Email:** admin@example.com
- **Password:** admin123
- **Role:** Administrator
- **Access:** Full system access, can create projects and manage users

## Owner Account
- **Email:** owner@example.com
- **Password:** owner123
- **Role:** Project Owner
- **Access:** Can view and manage assigned projects

## Contractor Account
- **Email:** contractor@example.com
- **Password:** contractor123
- **Role:** Contractor
- **Access:** Can view and manage assigned projects

## Important Notes

1. **Change these passwords immediately** after first login for security
2. These accounts are only created if no users exist in the database
3. If you delete the database, these accounts will be recreated on next startup
4. Admin users should create project-specific accounts for actual users

## Security Recommendations

- Change all default passwords before deploying to production
- Use strong, unique passwords for each account
- Consider enabling two-factor authentication for admin accounts
- Regularly review and update user permissions 