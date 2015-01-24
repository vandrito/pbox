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
#include <signal.h>
#include <ncurses.h>

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
    // for (unsigned int i = 0; i < strlen(reinterpret_cast<const char *>(s)); i++)
    for (unsigned int i = 0; i < strlen((const char *)s); i++)
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

        std::vector<std::vector<std::string>> entries;
 
        Crypto();
        ~Crypto();

        void clearMemory();
        int pandorasBox();
        void getPassword();
        void hashPassword(const char *in, char *out);
        void hashMasterKey(unsigned char *in, char *out);
        void createKey(const char *in, unsigned char *out);
        void readSecrets();
        int openPandorasBox();
};

Crypto::Crypto()
{
    this->clearMemory();

    randombytes(salt, sizeof salt);
    // std::cout << "\nSalt: " << salt << std::endl;
}
Crypto::~Crypto()
{
    std::ofstream out("zzzSuccessfulExit");
    out << "Test";
    out.close();
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

    for (unsigned int i = 0; i < this->entries.size(); i++)
    {
        for (unsigned int j = 0; j < this->entries[i].size(); j++)
        {
            memset(&this->entries[i][j], 0xd0, this->entries[i][j].length());
        }
    }
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
void Crypto::getPassword()
{
    printw("\nPassword: "); refresh();
    // std::cin.getline(this->password, 50);
    noecho();
    getstr(this->password);
    echo();

    clear();refresh();
}
void Crypto::hashPassword(const char *in, char *out)
{
    if (crypto_pwhash_scryptsalsa208sha256_str(
        out, in, strlen(in),
         crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
         crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        printw("\nOut of Memory"); refresh();
    }
}
void Crypto::hashMasterKey(unsigned char *in, char *out)
{
    if (crypto_pwhash_scryptsalsa208sha256_str(
        out, (const char *)in, strlen((const char *)in),
         crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
         crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        printw("\nOut of Memory"); refresh();
    }
}
void Crypto::createKey(const char *in, unsigned char *out)
{
    if (crypto_pwhash_scryptsalsa208sha256
        (out, sizeof out, in, strlen(in), this->salt,
         crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
         crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        printw("\nOut of Memory"); refresh();
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
int Crypto::openPandorasBox()
{
    // std::cout << this->hashedMasterKey;
    // std::cout << "\nPassword: " << this->password;
    //test password against hashed password
    if (crypto_pwhash_scryptsalsa208sha256_str_verify(
        this->hashedPassword, this->password, strlen(this->password)) != 0) 
    {
        printw("\nIncorrect Password"); refresh();
        this->getPassword();
    }

    //create testKey with password and salt
    this->createKey(this->password, this->testKey);

    //test testKey against hashed key
    if (crypto_pwhash_scryptsalsa208sha256_str_verify(
        this->hashedMasterKey, (const char *)this->testKey, 
        strlen((const char *)this->testKey)) != 0) 
    {
        printw("\nKeys Don't match\n"); refresh();
        char temp[10];
        getstr(temp);
        return 0;
    }
    else
    {
        printw("\nWelcome, Master!\n"); refresh();
        return 1;
    }
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

        void startUp();
        void startFresh();
        int checkCommand(std::string in, const char *test);
        void commandPrompt();
        void exit();
};


Interaction::Interaction()
{
    if (sodium_init() == -1)
    {
        printw("Sodium couldn't initialize\n"); refresh();
    }
    initscr();
    this->startUp();
}
Interaction::~Interaction()
{
    endwin();
}
void Interaction::startUp()
{
    //If we already have a key
    if (crypt.pandorasBox())
    {
        printw("\nOpen Pandora's Box\n"); refresh();
        crypt.getPassword();

        crypt.readSecrets();
        if (crypt.openPandorasBox())
        {
            this->commandPrompt();
        }
    }
    //If there is no key. Let's start fresh
    else
    {
        printw("\nCreate a new Pandora's Box\n"); refresh();
        this->startFresh();
        crypt.readSecrets();

        if (crypt.openPandorasBox())
        {
            this->commandPrompt();
        }
    }
}
void Interaction::startFresh()
{
    //Get password
    crypt.getPassword();
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
int Interaction::checkCommand(std::string in, const char *test)
{
    bool equal = true;

    // printw("%s %i\n", in.c_str(), strlen(in.c_str()));

    for (unsigned int i = 0;  i < strlen(test); i++)
    {
        if (in[i] != test[i])
        {
            equal = false;
            break;
        }
    }
    return equal;
}
void Interaction::commandPrompt()
{
    clear();refresh();
    printw("Enter a Command <h for help>\n> ");refresh();
    std::string command;
    getstr((char *)command.c_str());

    if (this->checkCommand(command, "h"))
    {
        clear();refresh();
        printw("this is the help dialog\n");refresh();
        char temp[10];
        getstr(temp);
        this->commandPrompt();
    }
    else if (this->checkCommand(command, "exit"))
    {
        this->exit();
    }
    else
    {
        this->commandPrompt();
    }
}
void Interaction::exit()
{
    //Empty to let program exit normally
    //Need to call destructors to clear memory
}




void exitGracefully(int sig)
{
    //Nothing here to block Ctrl+c and Ctrl+z
}
int main(void)
{
    signal(SIGINT, exitGracefully);
    signal(SIGTSTP, exitGracefully);
    Interaction *prompt = new Interaction;
    delete prompt;

    return 0;
}
