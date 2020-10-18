using IIG.PasswordHashingUtils;
using System;
using Xunit;

namespace XUnitTestPasswordHasher
{
    public class UnitTest1
    {
        // Test that result of GetHash function is not null
        [Fact]
        public void TestNotNull()
        {
            string pwd = "password";
            Assert.NotNull(PasswordHasher.GetHash(pwd));
        }

        // Test that result of GetHash function is not null for space password
        [Fact]
        public void SpacePassword()
        {
            string pwd = " ";
            Assert.NotNull(PasswordHasher.GetHash(pwd));
        }

        // Test that result of GetHash function is not null when password is empty string
        [Fact]
        public void EmptyPassword()
        {
            Assert.NotNull(PasswordHasher.GetHash(""));
        }

        // Test that result of GetHash function is not null for cyrillic password
        [Fact]
        public void CyrillicPassword()
        {
            string pwd = "пароль";
            Assert.NotNull(PasswordHasher.GetHash(pwd));
        }

        // Test that hashes for two same passwords are equal
        [Fact]
        public void SamePasswords()
        {
            string pwd = "password";
            Assert.Equal(PasswordHasher.GetHash(pwd), PasswordHasher.GetHash(pwd));
        }

        // Test that hashes for two different passwords are not equal
        [Fact]
        public void DifferentPasswords()
        {
            string pwd1 = "password1";
            string pwd2 = "password2";
            Assert.NotEqual(PasswordHasher.GetHash(pwd1), PasswordHasher.GetHash(pwd2));
        }

        // Test that hashes for two different letter register passwords are not equal
        [Fact]
        public void DifferentLetterRegister()
        {
            string pwd1 = "password";
            string pwd2 = "Password";
            Assert.NotEqual(PasswordHasher.GetHash(pwd1), PasswordHasher.GetHash(pwd2));
        }

        // Test that hashes for two same passwords and salts are equal
        [Fact]
        public void SameSalts()
        {
            string pwd = "password";
            string salt = "salt";
            Assert.Equal(PasswordHasher.GetHash(pwd, salt, null), PasswordHasher.GetHash(pwd, salt, null));
        }

        // Test that hashes for two same passwords and different salts are not equal
        [Fact]
        public void DifferentSalts()
        {
            string pwd = "password";
            string salt1 = "salt1";
            string salt2 = "salt2";
            Assert.NotEqual(PasswordHasher.GetHash(pwd, salt1, null), PasswordHasher.GetHash(pwd, salt2, null));
        }

        // Test that hashes for two same passwords are equal when one salt is empty and another one is null
        [Fact]
        public void DifferentSalts2()
        {
            string pwd = "password";
            string salt = "";
            Assert.Equal(PasswordHasher.GetHash(pwd, salt, null), PasswordHasher.GetHash(pwd, null, null));
        }

        // Test that hashes for two same passwords but without salt in first case are not equal
        [Fact]
        public void SaltAndNoSalt()
        {
            string pwd = "password";
            string salt = "salt";
            Assert.NotEqual(PasswordHasher.GetHash(pwd), PasswordHasher.GetHash(pwd, salt));
        }

        // Test that hashes for two same passwords and mod adler32 consts are equal
        [Fact]
        public void SameAdler32()
        {
            string pwd = "password";
            Assert.Equal(PasswordHasher.GetHash(pwd, null, 1111), PasswordHasher.GetHash(pwd, null, 1111));
        }

        // Test that hashes for two same passwords and different mod adler32 consts are not equal
        [Fact]
        public void DifferentAdler32()
        {
            string pwd = "password";
            Assert.NotEqual(PasswordHasher.GetHash(pwd, null, 1), PasswordHasher.GetHash(pwd, null, 23));
        }

        // Test that hashes are equal when all arguments are same
        [Fact]
        public void SameArguments()
        {
            string pwd = "password";
            string salt = "salt";
            Assert.Equal(PasswordHasher.GetHash(pwd, salt, 1111), PasswordHasher.GetHash(pwd, salt, 1111));
        }

        // Test that lenghts of hashes for two same passwords are equal
        [Fact]
        public void HashLengthSamePasswords()
        {
            string pwd = "password";
            Assert.Equal(PasswordHasher.GetHash(pwd).Length, PasswordHasher.GetHash(pwd).Length);
        }

        // Test that lenghts of hashes for two different passwords are not equal
        [Fact]
        public void HashLengthDifferentPasswords()
        {
            string pwd1 = "password1";
            string pwd2 = "password2";
            Assert.Equal(PasswordHasher.GetHash(pwd1).Length, PasswordHasher.GetHash(pwd2).Length);
        }

        // Test that hash has 64-symbol length
        [Fact]
        public void HashLength()
        {
            string pwd = "password";
            Assert.Equal(64, PasswordHasher.GetHash(pwd).Length);
        }

        // Test that password argument is necessary and can't be null
        [Fact]
        public void ArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => PasswordHasher.GetHash(null));
        }
    }
}
