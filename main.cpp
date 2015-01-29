#include <iostream>
#include <string>
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
    // sodium_memzero((void *)this->title.c_str(), strlen(this->title.c_str()-1));
    // sodium_memzero((void *)this->user.c_str(), strlen(this->user.c_str()-1));
    // sodium_memzero((void *)this->pw.c_str(), strlen(this->pw.c_str()-1));
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
void File::writeList(const unsigned char *key, std::vector<Entry> &entries)
{
    std::ofstream outfile(".list");

    // unsigned char key[crypto_secretbox_KEYBYTES];
    // randombytes_buf(key, sizeof key);

    for (unsigned int i = 0; i < entries.size(); i++)
    {
        //Write message length
        unsigned int messageLength = strlen((const char *)entries[i].title.c_str()) +strlen((const char *)entries[i].user.c_str())+strlen((const char *)entries[i].pw.c_str());
        messageLength += 2;
        outfile << std::hex << messageLength << "\n";

        //write nonce
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        while (sizeof nonce > strlen((const char *)nonce))
        {
            for (unsigned int i = 0; i < sizeof nonce; i++)
            {
                nonce[i] = randombytes_random();
            }
        }

        for (unsigned int i = 0; i < sizeof nonce; i++)
        {
            convert.ch = nonce[i];
            outfile << std::hex << convert.num << " ";
        }
        outfile << "\n";

        unsigned char message[messageLength];
        strcpy((char *)message, entries[i].title.c_str());
        strcat((char *)message, "\n");
        strcat((char *)message, entries[i].user.c_str());
        strcat((char *)message, "\n");
        strcat((char *)message, entries[i].pw.c_str());

        int ctLength = crypto_secretbox_MACBYTES + messageLength;
        unsigned char ciphertext[ctLength];
        crypto_secretbox_easy(ciphertext, (const unsigned char*)message, messageLength, nonce, key);

        for (int i = 0; i < ctLength; i++)
        {
            convert.ch = ciphertext[i];
            outfile << std::hex << convert.num << " ";
        }
        outfile << "\n";

        // sodium_memzero(message, messageLength);
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
};

Crypto::Crypto()
{
    this->clearMemory();

    while ( sizeof this->salt < strlen((const char *)this->salt))
    {
        randombytes(this->salt, sizeof this->salt);
    }
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
    getnstr(this->password, 50);
    echo();

    while (strlen(this->password) > 49)
    {
        clear();refresh();
        printw("\nPassword must be shorter than 50 characters\n");
        printw("\nPassword: "); refresh();
        noecho();
        getnstr(this->password, 50);
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
void Crypto::unlockList()
{
    Entry entry;
    std::ifstream infile(".list");

    std::string line;
    unsigned int linenum = 0;
    int messageLength;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    while (std::getline(infile, line))
    {
        if (linenum == 0)
        {
            // Read messagelength
            messageLength = strtol(line.c_str(), NULL, 16);
            linenum++;
        }
        else if (linenum == 1)
        {
            //Get Nonce
            std::string hex = "0x";
            std::string final = "";
            for (unsigned int i = 0; i < line.length(); i++)
            {
                if (isspace(line[i]))
                {
                    convert.num = strtol(hex.c_str(), NULL, 16);
                    final += convert.ch;
                    strcpy((char *)nonce, (const char *)final.c_str());

                    hex = "0x";
                }
                else
                {
                    hex += line[i];
                }
            }
            linenum++;
        }
        else if (linenum == 2)
        {
            //Read data
            std::string hex = "0x";
            std::string final = "";

            for (unsigned int i = 0; i < line.length(); i++)
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
            int ciphertextLength = crypto_secretbox_MACBYTES + messageLength;

            unsigned char decrypted[messageLength];

            if (crypto_secretbox_open_easy(decrypted, (unsigned char *)final.c_str(), ciphertextLength, nonce, this->testKey) != 0) {
            }
            else
            {
                std::string s;
                for (unsigned int i = 0; i < sizeof decrypted; i++)
                {
                    s+= decrypted[i];
                }
                std::string delimiter = "\n";
                sodium_memzero(decrypted, sizeof decrypted);

                size_t pos = 0;
                int l = 0;
                std::string token;
                while ((pos = s.find(delimiter)) != std::string::npos) {
                    token = s.substr(0, pos);

                    if (l == 0)
                    {
                        entry.title = token;
                        l++;
                    }
                    else if (l == 1)
                    {

                        entry.user = token;
                        l++;
                    }
                    s.erase(0, pos + delimiter.length());
                }
                entry.pw = "";
                for (unsigned int i = 0; i < s.length(); i++)
                {
                    entry.pw += s[i];
                }
                this->entries.push_back(entry);
            }
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
        int checkCommand(std::string in, const char *test);
        void commandPrompt();
        void newEntry();
        void listEntries();
        void getPassword(int entry);
        void editEntry();
        void deleteEntry();
        void getEntry();
        void helpDialog();
        void exit();
};


Interaction::Interaction()
{
    if (sodium_init() == -1)
    {
        printw("Sodium couldn't initialize\n"); refresh();
        char t[1];
        getstr(t);
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
    getstr((char *)command.c_str());

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
        while(strlen(tempInput.c_str()) > 50)
        {
            clear();refresh();
            printw("\nMust be shorter than 50 characters\n");
            printw("User> ");refresh();
            getnstr((char *)tempInput.c_str(),49);
        }
        strcpy((char *)tempEntry.user.c_str(), tempInput.c_str());
    }

    printw("\nPassword> ");refresh();
    getnstr((char *)tempInput.c_str(),49);
    if (memcmp ( tempInput.c_str(), enter, sizeof(enter) ) == 0)
    {
        strcpy((char *)tempEntry.pw.c_str(), "<NA>");
    }
    else
    {
        while(strlen(tempInput.c_str()) > 50)
        {
            clear();refresh();
            printw("\nMust be shorter than 50 characters\n");
            printw("Password> ");refresh();
            getnstr((char *)tempInput.c_str(),49);
        }
        strcpy((char *)tempEntry.pw.c_str(), tempInput.c_str());
    }
    tempInput = "00000000000000000000000000000000000000000000000000";

    crypt.entries.push_back(tempEntry);
    std::sort (crypt.entries.begin(), crypt.entries.end(), Entry());

}
void Interaction::getPassword(int entry)
{
    clear();refresh();
    printw("\n\t   Title> %s\n\n\t    User> %s\n\n\tPassword> %s\n", crypt.entries[entry].title.c_str(), crypt.entries[entry].user.c_str(), crypt.entries[entry].pw.c_str());

    char t[1];
    getstr(t);
}
void Interaction::listEntries()
{
    clear();refresh();

    int max = crypt.entries.size();
    int pos = 0;

    int input;
    while(input != 'q')
    {
        clear();refresh();
        printw("Listing Entries\n\n<q> to exit, <up/down> to scroll, <enter> to choose entry to view\n\n");
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
                getstr((char *)tempInput.c_str());

                int ii = strtol(tempInput.c_str(), NULL, 10) - 1;
                if ( ii < 0 || ii > (int)crypt.entries.size()-1)
                {
                    break;
                }
                else
                {
                    this->getPassword(ii);
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
            pos = max-10;
        }

    }
}
void Interaction::editEntry()
{
    clear();refresh();

    int max = crypt.entries.size();
    int pos = 0;

    int input;
    while(input != 'q')
    {
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
                std::string tempInput;
                getstr((char *)tempInput.c_str());

                int ii = strtol(tempInput.c_str(), NULL, 10) - 1;
                if ( ii < 0 || ii > (int)crypt.entries.size()-1)
                {
                    break;
                }
                else
                {
                    clear();
                    refresh();
                    std::string temp;
                    char enter[] = "";

                    clear();refresh();
                    printw("<Enter> to keep old data\n");
                    printw("\nOld Title> %s", crypt.entries[ii].title.c_str());
                    printw("\nNew Title> ");refresh();
                    getstr((char *)temp.c_str());
                    if (memcmp ( temp.c_str(), enter, sizeof(enter) ) == 0)
                    {
                        //Keep old entry
                    }
                    else
                    {
                        while(strlen(temp.c_str()) > 50)
                        {
                            clear();refresh();
                            printw("\nMust be shorter than 50 characters\n");
                            printw("\nOld Title> %s", crypt.entries[ii].title.c_str());
                            printw("\nNew Title> ");refresh();
                            getstr((char *)temp.c_str());
                        }
                        crypt.entries[ii].title = temp.c_str();
                    }

                    clear();refresh();
                    printw("<Enter> to keep old data\n");
                    printw("\nOld User> %s", crypt.entries[ii].user.c_str());
                    printw("\nNew User> ");refresh();
                    getstr((char *)temp.c_str());
                    if (memcmp ( temp.c_str(), enter, sizeof(enter) ) == 0)
                    {
                        //Keep old entry
                    }
                    else
                    {
                        while(strlen(temp.c_str()) > 50)
                        {
                            clear();refresh();
                            printw("\nMust be shorter than 50 characters\n");
                            printw("\nOld User> %s", crypt.entries[ii].user.c_str());
                            printw("\nNew User> ");refresh();
                            getstr((char *)temp.c_str());
                        }
                        crypt.entries[ii].user = temp.c_str();
                    }

                    clear();refresh();
                    printw("<Enter> to keep old data\n");
                    printw("\nOld Password> %s", crypt.entries[ii].pw.c_str());
                    printw("\nNew Password> ");refresh();
                    getstr((char *)temp.c_str());
                    if (memcmp ( temp.c_str(), enter, sizeof(enter) ) == 0)
                    {
                        //Keep old entry
                    }
                    else
                    {
                        while(strlen(temp.c_str()) > 50)
                        {
                            clear();refresh();
                            printw("\nMust be shorter than 50 characters\n");
                            printw("\nOld Password> %s", crypt.entries[ii].pw.c_str());
                            printw("\nNew Password> ");refresh();
                            getstr((char *)temp.c_str());
                        }
                        crypt.entries[ii].pw = temp.c_str();
                    }
                    temp = "00000000000000000000000000000000000000000000000000";
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
            pos = max-10;
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
void Interaction::getEntry()
{
    clear();refresh();
    printw("Get Entry\n\n");
    printw("> ");refresh();

    char enter[] = "";
    std::string entry;
    getstr((char *)entry.c_str());

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
                this->getPassword(i);

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
    printw("exit           Exit application");refresh();

    char t[1];
    getstr(t);
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
