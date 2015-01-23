#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include <termios.h>
#include <unistd.h>
// #include <cstdio>
// #include <cctype>
#include <vector>
// #include <climits>
// #include <sys/stat.h>

#include <sodium.h>

union Convert{
            char ch;
            uint32_t num;
        }convert;

/****************************************************
*
*                      FILE
*
*****************************************************/
class File{
    private:
        
    public:
        File();
        ~File();

        void storeSecrets(const char *pw, const char *k, const unsigned char *s);

};
File::File()
{

}
File::~File()
{

}
void File::storeSecrets(const char *pw, const char *k, const unsigned char *s)
{
    std::ofstream of(".pandorasBox");
    // std::cout << "\npw: " << pw << " " << strlen(pw);
    // std::cout << "\nk: " << k << " " << strlen(k);
    // std::cout << "\ns: " << s << " " << strlen(reinterpret_cast<const char *>(s));

    for (unsigned int i = 0; i < strlen(pw); i++)
    {
        convert.ch = pw[i];
        of << std::hex << convert.num << " ";
    }
    of << "\n";
    for (unsigned int i = 0; i < strlen(k); i++)
    {
        convert.ch = k[i];
        of << std::hex << convert.num << " ";
    }
    of << "\n";
    for (unsigned int i = 0; i < strlen(reinterpret_cast<const char *>(s)); i++)
    {
        convert.ch = s[i];
        of << std::hex << convert.num << " ";
    }
    of << "\n";

    of.close();
}


/****************************************************
*
*                      CRYPTO
*
*****************************************************/
class Crypto{
    private:
        File file;
    public:
        unsigned char masterKey[crypto_box_SEEDBYTES];
        char hashedMasterKey[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
        unsigned char testKey[crypto_box_SEEDBYTES];

        unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];

        char *password = new char [50];
        char hashedPassword[crypto_pwhash_scryptsalsa208sha256_STRBYTES];

        Crypto();
        ~Crypto();

        void clearMemory();
        int pandorasBox();
        void hashPassword(const char *in, char *out);
        void hashMasterKey(unsigned char *in, char *out);
        void createKey(const char *in, unsigned char *out);
        void readSecrets();
        void openPandorasBox();
        void getPassword();
};

Crypto::Crypto()
{
    this->clearMemory();

    randombytes(salt, sizeof salt);
    // std::cout << "\nSalt: " << salt << std::endl;
}
Crypto::~Crypto()
{
    this->clearMemory();
}
void Crypto::clearMemory()
{
    sodium_memzero(this->masterKey, crypto_box_SEEDBYTES);
    sodium_memzero(this->hashedMasterKey, crypto_pwhash_scryptsalsa208sha256_STRBYTES);
    sodium_memzero(this->testKey, crypto_box_SEEDBYTES);
    sodium_memzero(this->salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    sodium_memzero(this->password, 50);
    sodium_memzero(this->hashedPassword, crypto_pwhash_scryptsalsa208sha256_STRBYTES);
}
int Crypto::pandorasBox()
{
    std::ifstream pandorasBox(".pandorasBox");

    if (pandorasBox)
    {
        pandorasBox.close();
        return 1;
    }
    else
    {
        pandorasBox.close();
        return 0;
    }
}
void Crypto::hashPassword(const char *in, char *out)
{
    if (crypto_pwhash_scryptsalsa208sha256_str(
        out, in, strlen(in),
         crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
         crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        std::cout << "\nOut of Memory;";
    }
}
void Crypto::hashMasterKey(unsigned char *in, char *out)
{
    if (crypto_pwhash_scryptsalsa208sha256_str(
        out, reinterpret_cast<const char *>(in), strlen(reinterpret_cast<const char *>(in)),
         crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
         crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        std::cout << "\nOut of Memory;";
    }
}
void Crypto::createKey(const char *in, unsigned char *out)
{
    if (crypto_pwhash_scryptsalsa208sha256
        (out, sizeof out, in, strlen(in), this->salt,
         crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
         crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        std::cout << "\nOut of Memory;";
    }
}
void Crypto::readSecrets()
{
    std::ifstream inf(".pandorasBox");

    std::string character;
    std::string hex = "0x";
    std::string final;
    std::string line;

    std::getline(inf, line);
    for (unsigned int i = 0; i < strlen(line.c_str()); i++)
    {
        if (isspace(line[i]))
        {
            convert.num = strtol(hex.c_str(), NULL, 16);
            final += convert.ch;
            hex = "0x";
        }
        else
        {
            hex += line[i];
        }
    }
    strcpy(this->hashedPassword, final.c_str());

    final = "";
    std::getline(inf, line);
    for (unsigned int i = 0; i < strlen(line.c_str()); i++)
    {
        if (isspace(line[i]))
        {
            convert.num = strtol(hex.c_str(), NULL, 16);
            final += convert.ch;
            hex = "0x";
        }
        else
        {
            hex += line[i];
        }
    }
    strcpy(this->hashedMasterKey, final.c_str());

    final = "";
    std::getline(inf, line);
    for (unsigned int i = 0; i < strlen(line.c_str()); i++)
    {
        if (isspace(line[i]))
        {
            convert.num = strtol(hex.c_str(), NULL, 16);
            final += convert.ch;
            hex = "0x";
        }
        else
        {
            hex += line[i];
        }
    }
    for (unsigned int i = 0; i < strlen(final.c_str()); i++)
    {
        this->salt[i] = final[i];
    }

    // std::cout << "\nfinal: " << s <<"\n";
    // std::cout << "\nfinal: " << final <<"\n";

    inf.close();
}
void Crypto::openPandorasBox()
{
    // std::cout << this->hashedMasterKey;
    // std::cout << "\nPassword: " << this->password;
    //test password against hashed password
    if (crypto_pwhash_scryptsalsa208sha256_str_verify(
        this->hashedPassword, this->password, strlen(this->password)) != 0) 
    {
        std::cout << "\nIncorrect Password";
    }

    //create testKey with password and salt
    this->createKey(this->password, this->testKey);

    //test testKey against hashed key
    if (crypto_pwhash_scryptsalsa208sha256_str_verify(
        this->hashedMasterKey, reinterpret_cast<const char *>(this->testKey), 
        strlen(reinterpret_cast<const char *>(this->testKey))) != 0) 
    {
        std::cout << "\nKeys Don't match\n";
    }
    else
    {
        std::cout << "\nKeys match!\n";
    }
}
void Crypto::getPassword()
{
    std::cout << "\nPassword: ";
    std::cin.getline(this->password, 50);
}



/****************************************************
*
*                   INTERACTION
*
*****************************************************/
class Interaction{
    private:
        Crypto crypt;
        File file;
    public:
        Interaction();
        ~Interaction();
        void hideUserInput();
        void showUserInput();

        void startUp();
        void getSecrets();
        void startFresh();
};


Interaction::Interaction()
{
    if (sodium_init() == -1)
    {
        std::cout << "Sodium couldn't initialize\n";
    }
    this->startUp();
}
Interaction::~Interaction()
{

}
void Interaction::hideUserInput()
{
    termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}
void Interaction::showUserInput()
{
    termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}
void Interaction::startUp()
{
    if (crypt.pandorasBox())
    {
        std::cout << "\nOpen Pandora's Box\n";
        this->hideUserInput();
        crypt.getPassword();
        this->showUserInput();

        crypt.readSecrets();
        crypt.openPandorasBox();

        
    }
    else
    {
        std::cout << "\nCreate a new Pandora's Box\n";
        this->startFresh();

        crypt.readSecrets();
        crypt.openPandorasBox();
    }
}
void Interaction::getSecrets()
{
}
void Interaction::startFresh()
{
    //Get password
    this->hideUserInput();
    crypt.getPassword();
    this->showUserInput();
    //hash password
    crypt.hashPassword(crypt.password, crypt.hashedPassword);
    //create key
    crypt.createKey(crypt.password, crypt.masterKey);
    //hash key
    crypt.hashMasterKey(crypt.masterKey, crypt.hashedMasterKey);
    //store 
        // hash password
        // salt
        // hash key
    file.storeSecrets(crypt.hashedPassword, crypt.hashedMasterKey, crypt.salt);
}




int main(void)
{
    Interaction prompt;
    

    return 0;
}
