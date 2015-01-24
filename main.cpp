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

class Entry{
public:
    std::string title = "Qidj0yg<?lM_bD>IB:k5N?qIDJ~:qk&kuRtXG?.Rx!SL:x-00";
    std::string user = "Qidj0yg<?lM_bD>IB:k5N?qIDJ~:qk&kuRtXG?.Rx!SL:x-00";
    std::string pw = "Qidj0yg<?lM_bD>IB:k5N?qIDJ~:qk&kuRtXG?.Rx!SL:x-00";
    std::string future = "Qidj0yg<?lM_bD>IB:k5N?qIDJ~:qk&kuRtXG?.Rx!SL:x-00";

    Entry();
    ~Entry();
};
Entry::Entry()
{
    randombytes((unsigned char*)title.c_str(), 50);
    randombytes((unsigned char*)user.c_str(), 50);
    randombytes((unsigned char*)pw.c_str(), 50);
}
Entry::~Entry()
{
    sodium_memzero((void *)this->title.c_str(), strlen(this->title.c_str()-1));
    sodium_memzero((void *)this->user.c_str(), strlen(this->user.c_str()-1));
    sodium_memzero((void *)this->pw.c_str(), strlen(this->pw.c_str()-1));
}

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

        std::vector<Entry> entries;
 
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
        void newEntry();
        void listEntries();
        void editEntry();
        void deleteEntry();
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
    else if (this->checkCommand(command, "new"))
    {
        this->newEntry();
        this->commandPrompt();
    }
    else if (this->checkCommand(command, "list") || this->checkCommand(command, "ls"))
    {
        this->listEntries();
        this->commandPrompt();
    }
    else if (this->checkCommand(command, "edit"))
    {
        this->editEntry();
        this->commandPrompt();
    }
    else if (this->checkCommand(command, "delete"))
    {
        this->deleteEntry();
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
void Interaction::newEntry()
{
    clear();refresh();
    printw("\nNew Entry\n");

    Entry temp;
    printw("Title> ");refresh();
    getstr((char *)temp.title.c_str());

    printw("\nUser> ");refresh();
    getstr((char *)temp.user.c_str());

    printw("\nPassword> ");refresh();
    getstr((char *)temp.pw.c_str());

    crypt.entries.push_back(temp);
}
void Interaction::listEntries()
{
    clear();refresh();
    printw("\nListing Entries\n\n");

    if (crypt.entries.size() == 0)
    {
        printw("No Entries\n");
    }
    else
    {
        // printw("\t  %s\t\t\t%s\t\t%s", "Title", "Username", "Password\n\n");
        
        for (unsigned int i = 0; i < crypt.entries.size(); i++)
        {
            printw("\t%i: ", i+1);
            printw("%s\t\t%s\t\t%s", crypt.entries[i].title.c_str(), crypt.entries[i].user.c_str(), crypt.entries[i].pw.c_str());
            printw("\n");
        }
    }
    refresh();
    char t[1];
    getstr(t);
}
void Interaction::editEntry()
{
    clear();refresh();
    printw("\nChoose an entry to EDIT <0 to exit, ENTER to keep old data>\n\n");

    if (crypt.entries.size() == 0)
    {
        printw("No Entries\n");
    }
    else
    {
        // printw("\t  %s\t\t\t%s\t\t%s", "Title", "Username", "Password\n\n");
        
        for (unsigned int i = 0; i < crypt.entries.size(); i++)
        {
            printw("\t%i: ", i+1);
            printw("%s\t\t%s\t\t%s", crypt.entries[i].title.c_str(), crypt.entries[i].user.c_str(), crypt.entries[i].pw.c_str());
            printw("\n");
        }
    }
    printw("\n> ");refresh();

    char temp[8];
    getstr(temp);

    unsigned int entry = strtol(temp, NULL, 10);

    if (entry < 1 || entry > crypt.entries.size())
    {
        //Do nothing to finish if statement in commandPrompt()
    }
    else
    {
        entry--;
        clear();
        refresh();
        std::string temp;
        char enter[] = "";

        printw("\nOld Title> %s", crypt.entries[entry].title.c_str());
        printw("\nNew Title> ");refresh();
        getstr((char *)temp.c_str());
        if (memcmp ( temp.c_str(), enter, sizeof(enter) ) == 0)
        {
            //Keep old entry
        }
        else
        {
            crypt.entries[entry].title = temp.c_str();
            // getstr((char *)crypt.entries[entry].title.c_str());
        }

        printw("\nOld User> %s", crypt.entries[entry].user.c_str());
        printw("\nNew User> ");refresh();
        getstr((char *)temp.c_str());
        if (memcmp ( temp.c_str(), enter, sizeof(enter) ) == 0)
        {
            //Keep old entry
        }
        else
        {
            crypt.entries[entry].user = temp.c_str();
            // getstr((char *)crypt.entries[entry].title.c_str());
        }


        printw("\nOld Password> %s", crypt.entries[entry].pw.c_str());
        printw("\nNew Password> ");refresh();
        getstr((char *)temp.c_str());
        if (memcmp ( temp.c_str(), enter, sizeof(enter) ) == 0)
        {
            //Keep old entry
        }
        else
        {
            crypt.entries[entry].pw = temp.c_str();
            // getstr((char *)crypt.entries[entry].title.c_str());
        }

    }
}
void Interaction::deleteEntry()
{
    clear();refresh();
    printw("\nChoose an entry to DELETE <0 to exit>\n\n");

    if (crypt.entries.size() == 0)
    {
        printw("No Entries\n");
    }
    else
    {
        for (unsigned int i = 0; i < crypt.entries.size(); i++)
        {
            printw("\t%i: ", i+1);
            printw("%s\t\t%s\t\t%s", crypt.entries[i].title.c_str(), crypt.entries[i].user.c_str(), crypt.entries[i].pw.c_str());
            printw("\n");
        }
    }
    printw("\n> ");refresh();

    char temp[8];
    getstr(temp);

    unsigned int entry = strtol(temp, NULL, 10);

    if (entry < 1 || entry > crypt.entries.size())
    {
        //Do nothing to finish if statement in commandPrompt();
    }
    else
    {
        entry--;
        crypt.entries.erase(crypt.entries.begin() + entry);
    }
}




void exitGracefully(int sig)
{
    clear();refresh();
    printw("That is an unsafe operation");refresh();
}
int main(void)
{
    signal(SIGINT, exitGracefully);
    signal(SIGTSTP, exitGracefully);
    Interaction *prompt = new Interaction;
    delete prompt;

    return 0;
}
