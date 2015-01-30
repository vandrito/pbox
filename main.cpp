#include <iostream>
#include <string>
#include <sstream>
#include <cstring>
#include <fstream>
#include <termios.h>
#include <unistd.h>
// #include <cstdio>
// #include <cctype>
#include <vector>
#include <algorithm>
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
    std::string title = "00000000000000000000000000000000000000000000000000";
    std::string user = "00000000000000000000000000000000000000000000000000";
    std::string pw = "00000000000000000000000000000000000000000000000000";

    Entry();
    ~Entry();
    bool operator()(const Entry& x, const Entry&y) const
    {
        return x.title < y.title;
    }
};
Entry::Entry()
{
    // randombytes((unsigned char*)this->title.c_str(), 50);
    // randombytes((unsigned char*)this->user.c_str(), 50);
    // randombytes((unsigned char*)this->pw.c_str(), 50);
}
Entry::~Entry()
{
    this->title = "00000000000000000000000000000000000000000000000000";
    this->user = "00000000000000000000000000000000000000000000000000";
    this->pw = "00000000000000000000000000000000000000000000000000";
    //When creating new entries, the memzero function borks everything up
    sodium_memzero((void *)this->title.c_str(), strlen(this->title.c_str()));
    sodium_memzero((void *)this->user.c_str(), strlen(this->user.c_str()));
    sodium_memzero((void *)this->pw.c_str(), strlen(this->pw.c_str()));
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
        void writeList(const unsigned char *key, std::vector<Entry> &entries);

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
    
    char pwHex[strlen(pw)*2+1];
    sodium_bin2hex(
        pwHex, sizeof pwHex,
        (const unsigned char*)pw, strlen(pw));
    of << pwHex;
    of << "\n";
    
    char keyHex[strlen(k)*2+1];
    sodium_bin2hex(
        keyHex, sizeof keyHex,
        (const unsigned char*)k, strlen(k));
    of << keyHex;
    of << "\n";
    
    char sHex[strlen((const char *)s)*2+1];
    sodium_bin2hex(
        sHex, sizeof sHex,
        (const unsigned char*)s, strlen((const char *)s));
    of << sHex;
    of << "\n";

    of.close();
}
void File::writeList(const unsigned char *key, std::vector<Entry> &entries)
{
    std::ofstream outfile(".list");

    for (unsigned int i = 0; i < entries.size(); i++)
    {
        //Store title length in hex
        std::string title;
        int messageLength = strlen((const char *)entries[i].title.c_str());
        std::stringstream stream;
        stream << std::hex << messageLength;

        title += stream.str();
        title += ",";

        // Create nonce for title
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        while(sizeof nonce > strlen((const char *)nonce))
        {
            randombytes_buf(nonce, sizeof nonce);
        }

        //Store nonce for title
        char nonceHex[sizeof nonce*2+1];
        sodium_bin2hex(
            nonceHex, sizeof nonceHex,
            (const unsigned char*)nonce, sizeof nonce);
        title += nonceHex;
        title += ",";

        //Encrypt Title
        unsigned char ciphertext[crypto_secretbox_MACBYTES + messageLength];
        crypto_secretbox_easy(
            ciphertext, (const unsigned char *)entries[i].title.c_str(), messageLength,
            nonce, key);

        //Store User
        char ciphertextHex[sizeof ciphertext*2+1];
        sodium_bin2hex(
            ciphertextHex, sizeof ciphertextHex,
            (const unsigned char*)ciphertext, sizeof ciphertext);
        title += ciphertextHex;
        title += ",";

        outfile << title << "\n";

        //write user
        outfile << entries[i].user << "\n";

        //write password
        outfile << entries[i].pw << "\n";

        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero((void *)title.c_str(), sizeof title);
    }

    outfile.close();
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

        char password[50];
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
        void unlockList();
        void decryptHex(std::string &in, std::string &out);
        void encryptToHex(std::string &in, std::string &out);
};

Crypto::Crypto()
{
    this->clearMemory();

    while ( sizeof this->salt > strlen((const char *)this->salt))
    {
        randombytes_buf(this->salt, sizeof this->salt);
    }
}
Crypto::~Crypto()
{
    // std::ofstream out("zzzSuccessfulExit");
    // out << "Test";
    // out.close();
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
    std::ifstream list(".list");

    if (pandorasBox && list)
    {
        pandorasBox.close();
        list.close();
        return 1;
    }
    else
    {
        pandorasBox.close();
        list.close();
        return 0;
    }
}
void Crypto::getPassword()
{
    printw("\nPassword: "); refresh();
    noecho();
    getstr(this->password);
    echo();

    char enter[] = "";

    while (strlen(this->password) > 49 || memcmp( this->password, enter, sizeof(enter) ) == 0)
    {
        clear();refresh();
        printw("\nPassword must be shorter than 50 characters and greater than 0\n");
        printw("\nPassword: "); refresh();
        noecho();
        getstr(this->password);
        echo();
    }

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
    std::string line;
    int linenum = 0;

    while(std::getline(inf, line))
    {
        unsigned char bin[line.length()/2];
        size_t bin_len;
        const char *hex_end;

        int test = sodium_hex2bin(
            bin, sizeof bin,
            (const char *)line.c_str(), line.length(),
            NULL, &bin_len,
            &hex_end);
        if (test == 0)
        {
            if (linenum == 0)
            {
                strncpy((char *)this->hashedPassword, (const char *)bin, sizeof bin);

            }
            else if (linenum == 1)
            {
                strncpy((char *)this->hashedMasterKey, (const char *)bin, sizeof bin);
            }
            else if (linenum == 2)
            {
                strncpy((char *)this->salt, (const char *)bin, sizeof bin);
            }
        }
        linenum++;
    }

    inf.close();
}
int Crypto::openPandorasBox()
{
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
        sodium_memzero(this->password, 50);
        return 0;
    }
    else
    {
        printw("\nWelcome, Master!\n"); refresh();
        sodium_memzero(this->password, 50);
        return 1;
    }
}
void Crypto::decryptHex(std::string &in, std::string &out)
{
    unsigned int messageLength = 0;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    std::string decrypted;
    std::string ciphertext;

    std::string delimiter = ",";
    size_t pos = 0;
    int dl = 0;
    std::string token;
    std::string line = in;

    //for each comma delimited piece of the line
    while ((pos = line.find(delimiter)) != std::string::npos) 
    {
        token = line.substr(0, pos);
        if (dl == 0)
        {
            //Read in the title line length
            messageLength = strtol(token.c_str(), NULL, 16);
            dl++;
        }
        else if (dl == 1)
        {
            //Read in the title nonce
            unsigned char bin[24];
            size_t bin_len;
            const char *hex_end;

            if (sodium_hex2bin(
                bin, sizeof bin,
                (const char *)token.c_str(), 48,
                NULL, &bin_len,
                &hex_end) == 0)
            {
                strncpy((char*)nonce, (char*)bin, sizeof bin);
            }

            dl++;
        }
        else if (dl == 2)
        {
            //read in the title ciphertext as Hex
            unsigned char bin[token.length()/2];
            size_t bin_len;
            const char *hex_end;

            int test = sodium_hex2bin(
                bin, sizeof bin,
                (const char *)token.c_str(), token.length(),
                NULL, &bin_len,
                &hex_end);
            if (test == 0)
            {
                for (unsigned int i = 0; i < sizeof bin; i++)
                {
                    ciphertext += bin[i];
                }
            }
            else if (test == -1)
            {
                clear();
                printw("need more bytes");refresh();int t = getch();t++;
            }
            else
            {
                clear();
                printw("somethings messed up");refresh();int t = getch();t++;
            }

            // Decrypt Title
            int ciphertextLength = crypto_secretbox_MACBYTES + messageLength;
            if (crypto_secretbox_open_easy(
                (unsigned char *)decrypted.c_str(), 
                (unsigned char *)ciphertext.c_str(), 
                ciphertextLength, nonce, this->testKey) != 0) {
                clear();
                printw("forged");refresh();int t = getch();t++;
            }
            else
            {
                out = "";
                for (unsigned int i = 0; i < messageLength; i ++)
                {
                    out += decrypted[i];
                }
                sodium_memzero((void*)decrypted.c_str(), messageLength);
            }
        }
        //End of delimiter
        line.erase(0, pos + delimiter.length());
    }
}
void Crypto::encryptToHex(std::string &in, std::string &out)
{
    //Store message length in hex
    int messageLength = strlen((const char *)in.c_str());
    std::stringstream stream;
    stream << std::hex << messageLength;

    out = "";

    out += stream.str();
    out += ",";

    // Create nonce
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    while(sizeof nonce > strlen((const char *)nonce))
    {
        randombytes_buf(nonce, sizeof nonce);
    }

    //Store nonce
    char nonceHex[sizeof nonce*2+1];
    sodium_bin2hex(
        nonceHex, sizeof nonceHex,
        (const unsigned char*)nonce, sizeof nonce);
    out += nonceHex;
    out += ",";

    //Encrypt User
    unsigned char ciphertext[crypto_secretbox_MACBYTES + messageLength];
    crypto_secretbox_easy(
        ciphertext, (const unsigned char *)in.c_str(), messageLength,
        nonce, this->testKey);

    //Store User
    char ciphertextHex[sizeof ciphertext*2+1];
    sodium_bin2hex(
        ciphertextHex, sizeof ciphertextHex,
        (const unsigned char*)ciphertext, sizeof ciphertext);
    out += ciphertextHex;
    out += ",";
    sodium_memzero((void*)in.c_str(), messageLength);
}
void Crypto::unlockList()
{
    Entry entry;
    std::ifstream infile(".list");

    std::string line;
    unsigned int linenum = 0;

    //For each line
    while(std::getline(infile, line))
    {
        if (linenum == 0)
        {

            this->decryptHex(line, entry.title);
            linenum++;
        }
        else if (linenum == 1)
        {
            entry.user = line;
            linenum++;
        }
        else if (linenum == 2)
        {
            entry.pw = line;
            this->entries.push_back(entry);
            linenum = 0;

            
        }
    }
    infile.close();
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
        void pause();
        int checkCommand(std::string in, const char *test);
        void commandPrompt();
        void newEntry();
        void editEntry();
        void deleteEntry();
        void listEntries();
        void showPassword(int entry);
        void getEntry();
        void helpDialog();
        void changePassword();
        void exit();
};


Interaction::Interaction()
{
    if (sodium_init() == -1)
    {
        printw("Sodium couldn't initialize\n"); refresh();
        this->pause();
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
            crypt.unlockList();
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
            crypt.unlockList();
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
    //password checking was wonky without first creating an empty list
    std::ofstream list(".list");
    list.close();
}
void Interaction::pause()
{
    int t = getch();
    t++;
}
int Interaction::checkCommand(std::string in, const char *test)
{
    bool equal = true;

    for (unsigned int i = 0;  i < strlen(test); i++)
    {
        if (tolower(in[i]) != test[i])
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
    getnstr((char *)command.c_str(), 49);

    if (this->checkCommand(command, "h") || this->checkCommand(command, "help"))
    {
        this->helpDialog();
        this->commandPrompt();
    }
    else if (this->checkCommand(command, "new"))
    {
        this->newEntry();
        file.writeList(crypt.testKey, crypt.entries);
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
        file.writeList(crypt.testKey, crypt.entries);
        this->commandPrompt();
    }
    else if (this->checkCommand(command, "delete") || this->checkCommand(command, "del"))
    {
        this->deleteEntry();
        file.writeList(crypt.testKey, crypt.entries);
        this->commandPrompt();
    }
    else if (this->checkCommand(command, "get"))
    {
        this->getEntry();
        this->commandPrompt();
    }
    else if (this->checkCommand(command, "exit"))
    {
        this->exit();
    }
    else if (this->checkCommand(command, "change") || this->checkCommand(command, "change password"))
    {
        // this->changePassword();
        this->commandPrompt();
    }
    else
    {
        this->commandPrompt();
    }
}
void Interaction::newEntry()
{
    Entry tempEntry;
    char enter[] = "";
    std::string tempInput;

    clear();refresh();
    printw("\nNew Entry\n");

    printw("Title> ");refresh();
    getnstr((char *)tempInput.c_str(),49);
    if (memcmp ( tempInput.c_str(), enter, sizeof(enter) ) == 0)
    {
        strcpy((char *)tempEntry.title.c_str(), "<NA>");
    }
    else
    {
        while(strlen(tempInput.c_str()) > 50)
        {
            clear();refresh();
            printw("\nMust be shorter than 50 characters\n");
            printw("Title> ");refresh();
            getnstr((char *)tempInput.c_str(),49);
        }
        //Get title
        strcpy((char *)tempEntry.title.c_str(), tempInput.c_str());
    }

    printw("\nUser> ");refresh();
    getnstr((char *)tempInput.c_str(),49);
    if (memcmp ( tempInput.c_str(), enter, sizeof(enter) ) == 0)
    {
        strcpy((char *)tempEntry.user.c_str(), "<NA>");
    }
    else
    {
        tempInput = "";
        tempEntry.user = "";
        while(strlen(tempInput.c_str()) > 50)
        {
            clear();refresh();
            printw("\nMust be shorter than 50 characters\n");
            printw("User> ");refresh();
            getnstr((char *)tempInput.c_str(),49);
        }

        crypt.encryptToHex(tempInput, tempEntry.user);
    }

    printw("\nPassword> ");refresh();
    getnstr((char *)tempInput.c_str(),49);
    if (memcmp ( tempInput.c_str(), enter, sizeof(enter) ) == 0)
    {
        strcpy((char *)tempEntry.pw.c_str(), "<NA>");
    }
    else
    {
        tempInput = "";
        tempEntry.pw = "";
        while(strlen(tempInput.c_str()) > 50)
        {
            clear();refresh();
            printw("\nMust be shorter than 50 characters\n");
            printw("Password> ");refresh();
            getnstr((char *)tempInput.c_str(),49);
        }
        crypt.encryptToHex(tempInput, tempEntry.pw);
    }

    sodium_memzero((char *)tempInput.c_str(), sizeof tempInput);

    crypt.entries.push_back(tempEntry);
    std::sort (crypt.entries.begin(), crypt.entries.end(), Entry());
}
void Interaction::editEntry()
{
    clear();refresh();

    int max;
    int pos = 0;

    int input;
    while(input != 'q')
    {
        max = crypt.entries.size();
        clear();refresh();
        printw("Edit Entries\n\n<q> to exit, <up/down> to scroll, <enter> to choose entry to edit\n\n");
        if (max < 1)
        {
            printw("No Entries");
        }
        else
        {
            int maxShow = pos + 10;
            int counter = pos;

            if (maxShow > max)
            {
                maxShow = max;
            }
            for (;counter < maxShow; counter++)
            {
                printw("\t%i: %s\n", counter+1, crypt.entries[counter].title.c_str());
            }
        }
        keypad(stdscr, TRUE);
        input = getch();
        switch (input)
        {
            case KEY_UP:
            {
                pos -= 10;
                break;
            }
            case KEY_DOWN:
            {
                pos += 10;
                break;
            }
            case '\n':
            {
                // keypad(stdscr, FALSE);
                printw("\nentry> ");refresh();
                std::string entryNumber;
                getnstr((char *)entryNumber.c_str(), 49);

                int entryNum = strtol(entryNumber.c_str(), NULL, 10) - 1;
                if ( entryNum < 0 || entryNum > (int)crypt.entries.size()-1)
                {
                    break;
                }
                else
                {
                    clear();
                    refresh();
                    std::string tempInput;
                    char enter[] = "";

                    clear();refresh();
                    printw("<Enter> to keep old data\n");
                    printw("\nOld Title> %s", crypt.entries[entryNum].title.c_str());
                    printw("\nNew Title> ");refresh();
                    getnstr((char *)tempInput.c_str(), 49);
                    if (memcmp ( tempInput.c_str(), enter, sizeof(enter) ) == 0)
                    {
                        //Keep old entry
                    }
                    else
                    {
                        while(strlen(tempInput.c_str()) > 50)
                        {
                            clear();refresh();
                            printw("\nMust be shorter than 50 characters\n");
                            printw("\nOld Title> %s", crypt.entries[entryNum].title.c_str());
                            printw("\nNew Title> ");refresh();
                            getnstr((char *)tempInput.c_str(), 49);
                        }
                        crypt.entries[entryNum].title = tempInput.c_str();
                    }

                    std::string user;
                    crypt.decryptHex(crypt.entries[entryNum].user, user);
                    tempInput = "";

                    clear();refresh();
                    printw("<Enter> to keep old data\n");
                    printw("\nOld User> %s", user.c_str());
                    printw("\nNew User> ");refresh();
                    getnstr((char *)tempInput.c_str(), 49);
                    if (memcmp ( tempInput.c_str(), enter, sizeof(enter) ) == 0)
                    {
                        //Keep old entry
                    }
                    else
                    {
                        while(strlen(tempInput.c_str()) > 50)
                        {
                            clear();refresh();
                            printw("\nMust be shorter than 50 characters\n");
                            printw("\nOld User> %s", user.c_str());
                            printw("\nNew User> ");refresh();
                            getnstr((char *)tempInput.c_str(), 49);
                        }
                        crypt.encryptToHex(tempInput, crypt.entries[entryNum].user);
                    }

                    std::string pw;
                    crypt.decryptHex(crypt.entries[entryNum].pw, pw);
                    tempInput = "";

                    clear();refresh();
                    printw("<Enter> to keep old data\n");
                    printw("\nOld Password> %s", pw.c_str());
                    printw("\nNew Password> ");refresh();
                    getnstr((char *)tempInput.c_str(), 49);
                    if (memcmp ( tempInput.c_str(), enter, sizeof(enter) ) == 0)
                    {
                        //Keep old entry
                    }
                    else
                    {
                        while(strlen(tempInput.c_str()) > 50)
                        {
                            clear();refresh();
                            printw("\nMust be shorter than 50 characters\n");
                            printw("\nOld Password> %s", pw.c_str());
                            printw("\nNew Password> ");refresh();
                            getnstr((char *)tempInput.c_str(), 49);
                        }
                        crypt.encryptToHex(tempInput, crypt.entries[entryNum].pw);
                    }
                    tempInput = "00000000000000000000000000000000000000000000000000";
                    std::sort(crypt.entries.begin(), crypt.entries.end(), Entry());
                }
                break;
            }
        }
        keypad(stdscr, FALSE);

        if (pos < 0)
        {
            pos = 0;
        }
        else if (pos > max-10)
        {
            if (max < 10)
            {
                pos = 0;
            }
            else
            {
                pos = max-10;
            }
        }

    }
}
void Interaction::deleteEntry()
{
    clear();refresh();

    int max;
    int pos = 0;

    int input;
    while(input != 'q')
    {
        max = crypt.entries.size();
        clear();refresh();
        printw("Delete Entries\n\n<q> to exit, <up/down> to scroll, <enter> to choose entry to delete\n\n");
        if (max < 1)
        {
            printw("No Entries");
        }
        else
        {
            int maxShow = pos + 10;
            int counter = pos;

            if (maxShow > max)
            {
                maxShow = max;
            }
            for (;counter < maxShow; counter++)
            {
                printw("\t%i: %s\n", counter+1, crypt.entries[counter].title.c_str());
            }
        }
        keypad(stdscr, TRUE);
        input = getch();
        switch (input)
        {
            case KEY_UP:
            {
                pos -= 10;
                break;
            }
            case KEY_DOWN:
            {
                pos += 10;
                break;
            }
            case '\n':
            {
                // keypad(stdscr, FALSE);
                printw("\nentry> ");refresh();
                std::string tempInput;
                getnstr((char *)tempInput.c_str(),49);

                int ii = strtol(tempInput.c_str(), NULL, 10) - 1;
                if ( ii < 0 || ii > (int)crypt.entries.size()-1)
                {
                    break;
                }
                else
                {
                    crypt.entries.erase(crypt.entries.begin() + ii);
                    break;
                }
                break;
            }
        }
        keypad(stdscr, FALSE);

        if (pos < 0)
        {
            pos = 0;
        }
        else if (pos > max-10)
        {
            if (max < 10)
            {
                pos = 0;
            }
            else
            {
                pos = max-10;
            }
        }
    }
}
void Interaction::listEntries()
{
    clear();refresh();

    int max;
    int pos = 0;

    int input = 0;
    while(input != 'q')
    {
        max = crypt.entries.size();
        clear();refresh();
        printw("Listing Entries\n\n<q> to exit, <up/down> to scroll, <enter> to choose entry to view\n\n");
        if (max < 1)
        {
            printw("No Entries");refresh();
        }
        else
        {
            int maxShow = pos + 10;
            int counter = pos;

            if (maxShow > max)
            {
                maxShow = max;
            }
            for (;counter < maxShow; counter++)
            {
                printw("\t%i: %s\n", counter+1, crypt.entries[counter].title.c_str());
            }
        }
        keypad(stdscr, TRUE);
        input = getch();
        switch (input)
        {
            case KEY_UP:
            {
                pos -= 10;
                break;
            }
            case KEY_DOWN:
            {
                pos += 10;
                break;
            }
            case '\n':
            {
                // keypad(stdscr, FALSE);
                printw("\nentry> ");refresh();
                std::string tempInput;
                getstr((char *)tempInput.c_str());



                if ((int)strtol(tempInput.c_str(), NULL, 10) == '\n')
                {
                    break;
                }

                int ii = strtol(tempInput.c_str(), NULL, 10) - 1;
                if ( ii < 0 || ii > (int)crypt.entries.size()-1)
                {
                    break;
                }
                else
                {
                    this->showPassword(ii);
                }
                break;
            }
        }
        keypad(stdscr, FALSE);

        if (pos < 0)
        {
            pos = 0;
        }
        else if (pos > max-10)
        {
            if (max < 10)
            {
                pos = 0;
            }
            else
            {
                pos = max-10;
            }
        }

    }
}
void Interaction::showPassword(int entry)
{

    std::string user;
    std::string pw;

    crypt.decryptHex(crypt.entries[entry].user, user);
    crypt.decryptHex(crypt.entries[entry].pw, pw);

    clear();refresh();
    printw("\n\t   Title> %s\n\n\t   User> %s\n\n\tPassword> %s",
        crypt.entries[entry].title.c_str(),user.c_str(),pw.c_str());
    refresh();
    
    sodium_memzero((void*)user.c_str(), sizeof user);
    sodium_memzero((void*)pw.c_str(), sizeof pw);

    this->pause();
}
void Interaction::getEntry()
{
    clear();refresh();
    printw("Get Entry\n\n");
    printw("> ");refresh();

    char enter[] = "";
    std::string entry;
    getnstr((char *)entry.c_str(), 49);

    if (memcmp ( entry.c_str(), enter, sizeof(enter) ) == 0)
    {
        //Do nothing to go back to command prompt
    }
    else
    {
        for (unsigned int i = 0; i < crypt.entries.size(); i++)
        {
            if (crypt.entries[i].title.find((const char *)entry.c_str(), 0) != std::string::npos)
            {
                this->showPassword(i);

                break;
            }
        }
    }
}
void Interaction::helpDialog()
{
    clear();refresh();
    printw("List of Commands\n\n");
    printw("new            Create a new entry\n");
    printw("edit           Edit an existing entry\n");
    printw("delete,del     Remove an existing entry\n");
    printw("list,ls        List current entries\n");
    printw("get            Get an entry and view it\n");
    printw("change         Change password\n");
    printw("exit           Exit application");refresh();

    this->pause();
}
void Interaction::changePassword()
{
    clear();refresh();
    printw("Change Password\n");
    //Get password
    crypt.getPassword();
    //hash password
    crypt.hashPassword(crypt.password, crypt.hashedPassword);

    //Need new salt
    randombytes_buf(crypt.salt, sizeof crypt.salt);
    while ( sizeof crypt.salt > strlen((const char *)crypt.salt))
    {
        randombytes_buf(crypt.salt, sizeof crypt.salt);
    }

    //create key
    crypt.createKey(crypt.password, crypt.masterKey);
    //hash key
    crypt.hashMasterKey(crypt.masterKey, crypt.hashedMasterKey);
    //store 
        // hash password
        // salt
        // hash key
    file.storeSecrets(crypt.hashedPassword, crypt.hashedMasterKey, crypt.salt);
    // file.writeList(crypt.masterKey, crypt.entries);
    sodium_memzero(crypt.masterKey, sizeof crypt.masterKey);
}
void Interaction::exit()
{
    //Empty to let program exit normally
    //Need to call destructors to clear memory
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
