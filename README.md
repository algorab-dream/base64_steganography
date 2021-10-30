# base64_steganography

Hide and recover data from a plain text and its base64-encoded string !

Thanks to the fact that characters are encoded in 6 bits in a base 64 encoded text,
it is possible to hide data in a base 64 text, by using the padding.

Therefore, you won't loose any information about your support text, as far as the 
hidden data will be put in the "free bits" gained by padding.

Any contribution, such as implementing the base 32 steganography tool using the same
principle, is welcome :)

Feel free to use and distribute this little code !
