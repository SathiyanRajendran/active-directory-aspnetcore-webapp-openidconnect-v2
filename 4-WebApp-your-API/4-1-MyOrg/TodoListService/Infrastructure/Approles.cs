namespace TodoListService.Infrastructure
{
    //public static class Role
    //{
    //    public const string UserReaders = "UserReaders";
    //    public const string DirectoryViewers = "DirectoryViewers";
    //}
    //public static class AuthorizationPolicies
    //{
    //    public const string AssignmentToUserReaderRoleRequired = "AssignmentToUserReaderRoleRequired";
    //    public const string AssignmentToDirectoryViewerRoleRequired = "AssignmentToDirectoryViewerRoleRequired";
    //}

    public static class ApplicationRole
    {
        public const string roleForCreate = "UserandAdmin";
        public const string roleForEdit = "Admin";
        public const string roleForView = "UserandAdmin";
        public const string roleForDetails = "UserandAdmin";
        public const string roleForDelete = "Admin";
    }
}
