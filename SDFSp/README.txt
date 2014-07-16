README.txt




1. Port Numbers:

Choose any unused port


Warning Warning: 

If 'Connection Refused' error received during implementation of the program, simply restart the program, this means that the port that communication is occurring was not properly unbound. Upon restarting the program, pick an unused port. In unix perform 'netstat -an | grep <port number> to check if a given port is bound/listening. 

2. Host Address

Host address of choice = 'localhost' or '127.0.0.1' <without the single quotes>. Any address of this form can be used as long as it's a legal protocal address. 

3. File UID

Instead of file UID's, file names and path names were used. When asked for a file name, input the name of the file. For example, 'test.txt'. When asked for a path name for a file, input something similar to './trish/text.txt'. 

4. Menu

A. New Client

Input a username and password. 

B. Start

i. Start-FS-Session 

Input client name and password. The session initailization will begin afterwards. 

ii. Get(file UID)

Input client name, password, file name, and path name for file. System will first check if file exists, then check if client has rights to perform Get() operation on file. Get() operation will fail if client does not have designated rights.

iii. Put(file UID)

Input client name, password, file name, and path name for file. System will first check if file exists, then check if client has rights to perform Put() operation on file. Put() operation will fail if client does not have designated rights.

iv. Delegation/Delegation*(File UID, Client Cert C, time duration)

Input username and password of client who will be authorizing the delegation. Input username of client who is the recepient of the delegation. Enter the delegation rights receipient will receive, and time duration of these delegation rights in minutes. 

vi.Exit

Quit menu by selecting option 5 or 6. Then selection Option 3 of the main menu. This is recommended so that the server port will be closed successfully. 



