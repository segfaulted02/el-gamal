# el-gamal
Implementation of the El Gamal cryptosystem.

Utilizes the concepts of Sophie Germain primes and safe primes to compute keys.

Running time is heavily affected by random number generation, and attempts were made to speed it up, which worked to a degree.
1024 bit numbers can be effectively created in a reasonable amount of time, however 2048 bit numbers are exponentially longer.

By running the Python file, you can encrypt, decrypt, and generate keys.

Not very pretty looking code, ideally could move functions around to other files, but for the scope of this project, just a straightforward implementation.

Limitations of this code exist when input plaintext messages are long, where the program cannot effectively decrypt these messages. Likely an issue where the encryption and size of key is not always compatible, causing an issue where smaller keys cause issues in decryption.
