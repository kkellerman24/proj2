Kevin Kellerman - README.txt

Four files were involved in this new test program.

After a seach using Grep, I created alarm-mega.ck which is the same file
as alarm-multiple.ck, except check_alarm was passed 70 instead of 7. I am
not sure if this impacts the running of the test program or not.

Edit of test.h:      Added the same header as alarm-multiple but with alarm-mega
Edit of test.c:      Added the same line as alarm-multiple but with alarm-mega and 70 alarms.
Edit of alarm-wait.c:Added alarm-mega function with 5 threads and 70 alarms. 


