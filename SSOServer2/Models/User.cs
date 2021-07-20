namespace SSOServer2.Models
{
    public class User
{
    public User() { }
    public User(int id, string firstName, string lastName, string email, string password, string[] roles) =>
    (Id, FirstName, LastName, Email, Password, Roles) = (id, firstName, lastName, email, password, roles);
    public int Id { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
    public string[] Roles { get; set; }
}

}
