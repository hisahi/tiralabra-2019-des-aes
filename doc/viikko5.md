# Tehdyt asiat
Lisäsin -test-tuen, salasanatuen, IV-tuen (joten nyt käyttöohjeessa mainitut
asiat oikeasti toimivat) sekä kirjoitin testausdokumenttiin tekemieni
testien tuloksia.

Toteutuksia varten olen toteuttanut lisäksi MT19937-
satunnaislukugeneraattorin (jotta pääsisi Randomista eroon) sekä ChaCha20-
jonosalaajan, jota käytetään kryptografisesti vahvojen satunnaislukujen
generointiin (jonka apukoodi löytyy Utils-luokasta).

# Mitä olen oppinut
Kryptografisesti turvallisten satunnaislukugeneraattorien perustat,
ChaCha20-algoritmin sekä testeistä opitut asiat.

# Seuraavaksi
Paljoa ei ole jäljellä - (heikkojen) satunnaislukujen generointiin voisi
vielä luoda oman algoritmin. Käyttöliittymässä itsessään on vielä vähän
hiottavaa.

# Vaikeudet
ChaCha20-salain jota käytetään vahvojen satunnaisten arvojen luomiseen
tuotti ongelmia, jossa tuloksissa oli yhden bitin virhe. Tämän syyn
selvittämisessä kesti (ei pitänyt kasvattaa laskuria lopputuloksessa vaan
avainlohkossa, jotka olivat tosiaan erikseen).

# Aika
Käytetty aika noin 12 tuntia.
