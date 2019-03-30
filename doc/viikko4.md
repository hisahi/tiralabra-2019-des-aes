# Tehdyt asiat
Toteutin tällä viikolla sekä SHA1- että SHA2-tiivistysmenetelmät, HMAC-koodin sekä PBKDF2-avaimenjohtamisfunktion. Tämän lisäksi kirjoitin toteutus- ja testausdokumenttiin jonkinlaisen alun.

# Mitä olen oppinut
SHA1- ja SHA2-algoritmien toimintaperiaatteet, samoin HMAC:n ja PBKDF2:n. 

# Seuraavaksi
Seuraavaksi työnä on yhdistää PBKDF2 käyttöliittymään niin, että avaimen sijasta voi käyttää salasanaa. Tätä varten tulee myös luoda tuki avaimen ja IV:n lukemiseksi tiedostosta komentorivitoiminnon sijaan. Kun salasana on toteutettu, kaikkia kolmea algoritmia voidaan vertailla samoilla tiedoilla.

# Vaikeudet
Hankalin osa oli toteutus- ja testausdokumentin kirjoitus, eikä sekään ollut hankalaa. SHA1- ja SHA2-toteutukset sekä HMAC ja PBKDF2 menivät yllättävän sulavasti; edellä mainitusta kaksi meni ensimmäisellä kerralla oikein ilman testejäkin.

# Aika
Käytetty aika noin 6 tuntia.
