# Another POC
    After you map with kdmapper just free all mapped memory.
    use (MmFreePagesFromMdl and FreePool) 
    and you will only have one page allocated

    in this method i am using .data ptr to communicate (NtUserGetObjectInformation) (https://www.unknowncheats.me/forum/anti-cheat-bypass/425352-driver-communication-using-data-ptr-called-function.html)
    but you can use any kind of communication


# Visual studio project
# Properties -> C/C++ -> Optimization
    Full program optimization (Yes (/GL))
# Properties -> C/C++ -> Code generation
    Security Check (Disable Security Check (/GS-))
    Control flow protection (No)


# TODO

Replace KeAttachProcess with my Custom AttachProcess    
    https://github.com/EBalloon/Rw-No-Attach
