using SSOServer2.Models; 
using System.Collections.Generic;
using System.Linq;

namespace SSOServer2.Data
{
    public class Repository
    {
        private static readonly List<User> Users = new()
        {
            new User(1, "Maria", "Sanders", "msanders@northwind.com", "12345",
            new string[]{"Admin" }),
            new User(2, "Pedro", "Flores", "pflores@northwind.com", "12345",
            new string[]{"Accountant" }),
            new User(3, "Estela", "Castillo", "ecastillo@northwind.com", "12345",
            new string[]{"Seller" }),
            new User(4, "Gloria", "Ruiz", "gruiz@northwind.com", "12345",
            new string[]{"Seller", "Accountant"})
         };

        public static User GetUser(string email, string password)
        {
            return Users.FirstOrDefault(u => u.Email == email && u.Password == password);
        }
    }

}
