# Toteutus
Ohjelma toteuttaa kolme eri lohkosalausalgoritmia: DES, 3DES sekä AES. Vaikka
jokaisessa ohjelmoijalle näkyvä osa on samanlainen (syötä tietynkokoinen
"lohko" dataa, joka puretaan tai salataan annetulla avaimella),
toimintaperiaatteet ovat oikeastaan pintaa syvemmältä huomattavankin
erilaiset. Lohkosalausalgoritmia käyttäessä tulee myös valita
lohkosalaustila, joita ohjelma tarjoaa kolme: ECB, CBC and CTR.

# Salaus

## DES
DES, eli Data Encryption Standard, käyttää yhden lohkon salaukseen 16
kierrosta vuorotellen vasempaan ja oikeaan osaan sovellettua niin sanottua
Feistel-funktiota, joka ensin laajentaa avaimen, sekoittaa sen annettuun
lohkoon, korvaa laajennetun arvon osat käyttäen S-boxia (joka käytännössä 
on vain hakutaulu) ja lopuksi permutoi bittejä ympäri.

DES:iä pidetään nykyään epäturvallisena eikä sitä enää suositella käytettäväksi
tiedon salaamiseen. DES:n lohkokoko on 64 bittiä ja avainkoko 64 bittiä, tosin
niistä 8 bittiä ovat pariteettia ja siten avaimia on vain 2^56.

Algoritmin tilavaativuus on vakio. Suurimman osan dynaamisesti varattavasta
tilasta vie avainlista, jonka koko on kuitenkin vakio eikä riipu esimerkiksi
salattavan tiedon määrästä. Aikavaativuus taas riippuu lineaarisesti
tiedon määrästä ja on siten O(n), sillä esimerkiksi Feistelin funktio
ei muutu datan määrästä riippuen.

## Triple-DES, 3DES
Tämä salausalgoritmi toimii yksinkertaisesti kolminkertaisella DES:llä.
Esimerkiksi yhden lohkon salauksessa lohko salataan DES:llä ensimmäisellä
avaimella, puretaan toisella ja salataan kolmannella. Kolmea avainta
käytetään kahden sijasta, koska kahden avaimen käyttäminen ei lisäisi
kryptografista turvallisuutta juuri lainkaan riippuen keskikohtahyökkäyksestä
(_meet-in-the-middle attack_), jossa `C = ENC2(ENC1(P))` muuttuu muotoon 
`DEC2(C) = ENC1(P)` ja vaatisi `2^K * 2^K` avainparin tarkistuksen sijasta vain
`2^(K+1)` avainparin tarkistusta. Triple-DES pysyi käytössä pidempään kuin
DES, mutta sitäkin pidetään nykyään epäturvallisena.

Algoritmin tilavaativuudet ja aikavaativuudet ovat samat kuin DES-algoritmilla,
koska niihin vaikuttaa ainoastaan vakiokerroin (3).

## AES
AES:n toimintaperiaate on pinnan alta hyvinkin erilainen. Se käyttää 128 bitin
eli 16 tavun lohkoja, jotka esitetään 4x4 matriisina. Kierrokset koostuvat
avaimeen pohjautuvan avainluettelon ala-avainten lisäämisestä taulukkoon,
tavujen korvaamisesta AES:n omalla S-boxilla, rivien siirtämisestä ja
sarakepohjaisesta lineaarisesta operaatiosta Galoisin kentän avulla.

Samoin kuin DES, AES:n tilavaativuus on vakio, josta avainluettelo vie
suurimman osan muistia. Aikavaativuus on myös O(n), sillä mikään AES:n
kierroksen osa ei riipu salattavan lohkon sisällöstä tai sen koosta. Ainoa
AES:n kokoon ja aikaan vaikuttava muuttuja on avaimen koko, joten aika-
ja tilavaativuuden voisikin ilmaista k:n eli avaimen koon perusteella. Suhde
ei ole kuitenkaan lineaarinen vaan logaritminen (128 bitin avaimella
kierroksia tehdään 10, 192 bitin avaimella 12 ja 256 bitin avaimella 14). Siten
aikavaativuus on O(n log k) ja tilavaativuus O(log k). Todellisuudessa
kuitenkin aikavaativuus O(n) ja tilavaativuus O(1) on parempi esitystapa.

## Lohkotilat
Kolme lohkotilaa ECB, CBC ja CTR ovat kaikki aikavaativuudeltaan O(n) ja
tilavaativuudeltaan O(1). 

ECB ei muuta lainkaan läpi kulkevia lohkoja (joten
samanlaiset selkokieliset lohkot muuttuvat samankaltaisiksi salatuiksi
lohkoiksi, joka voi [paljastaa tietoja salatunkin datan rakenteesta](
https://commons.wikimedia.org/wiki/File:Tux_ecb.jpg)).

CBC yhdistää salatun lohkon seuraavaan selkokieliseen lohkoon XOR-operaatiolla
ennen salausta ja purettaessa tämä prosessi tapahtuu toiseen suuntaan. Toisin
kuin ECB, CBC vaatii myös alustusvektorin (IV), joka yhdistetään ensimmäiseen
selkokieliseen lohkoon, sillä edellistä salattua lohkoa ei vielä ole.

CTR taas salaa oikeasti alustusvektorin ja kasvavan laskurin XOR-yhdistelmän
ja salaa selkokielisen lohkon XOR-operaatiolla tuloksena saatuun lohkoon.

## Täydennys
StreamBlockReader osaa lukea mistä tahansa tavuvirrasta algoritmille
sopivan kokoisia lohkoja. Tämän lisäksi niihin sovelletaan PKCS#5/PKCS#7
-täydennystä (_padding_), jonka mukaan osittainen lohko täydennetään tavuilla, 
joiden arvo vastaa lisättävien täydennystavujen lukumäärää. Jos tavuvirta 
loppuu sopivasti niin että tieto jakautuu tasan lohkoihin, viimeiseksi lohkoksi
lisätään täydennetty tyhjä lohko, eli esimerkiksi 8 tavun lohkokoolla
lopussa olisi 8 tavun lohko tavuja, joiden jokaisen arvo on 8.

# Mittauksia
Tarkempaa tietoa löytyy testausdokumentista.

Nopeassa testauksessa DES on noin 1/20 OpenSSL:n suorituskyvystä ja AES
noin 1/8. Kaikkia algoritmeja on testattu OpenSSL:ää sekä muita salaus-
ohjelmia vastaan, ja salatut syötteet ovat yhteensopivia. 

# Ohjelman rakenne
Ohjelman rakenteesta käytetään laajasti hyödyksi olio-ohjelmoinnin
rakenteita, kuten rajapintoja (protokollia) sekä luokkia. Esimerkiksi kaikki
salausalgoritmit ja lohkotilat perustuvat rajapintaan, jonka mukaan
niiden on toteutettava alustus, lohkon käsittely ja lopetus. Tarkempi
rakenne esimerkiksi tiedoston salaukseen on seuraava:

1. Annettu tiedosto avataan.
2. Lohkotila ja salausalgoritmi alustetaan annetulla avaimella ja
   aloitusvektorilla. Tämän lisäksi alustetaan täydennystä tarjoava
   StreamBlockReader.
3. Kunnes lohkot loppuvat:
  1. Luetaan yksi lohko StreamBlockReaderista. Jos lohko vaatii
     täydennystä, luokka osaa lisätä sen; muussa tapauksessa lohko
     on sama kuin tavuvirrasta lue tieto.
  2. Kyseinen lohko annetaan lohkotilan toteuttavalle luokalle.
  3. Tämä luokka taas salaa lohkon annetulla salausalgoritmilla ja
     palauttaa saamansa lohkon.
  4. Saatu lohko kirjoitetaan ulostulotiedostoon.

Kun salaus tai purku on tehty onnistuneesti, ohjelma kertoo lopussa
kuluneen muistin ja ajan. Ajasta kerrotaan kaksi lukua: kesto yhteensä
ja arvio siitä, miten pitkään juuri salaus tai purku kesti. Näiden
arvojen perusteella lasketaan keskimääräinen salaus- tai purkunopeus.
Vaikka aikamittaukset voisivat teknisesti olla nanosekunnin tasolla,
monet käyttöjärjestelmät eivät oikeasti tarjoa niin suurta tarkkuutta.

Kaikkiin ohjelman osiin jotka eivät ole itsestään selviä, paitsi
käyttöliittymän koodiin, on sisällytetty Javadocs-dokumentaatio, joka kertoo
luokkien ja niiden metodien tarkoituksen. Asiaa selventäviä kommentteja
löytyy myös kaikkialta koodista.

Avain voi olla myös salasana, jolloin alustusvektori ja salasanan suola-arvo
(salt) luodaan satunnaisesti salatessa ja vaaditaan purkaessa. Salasana
muutetaan avaimeksi käyttämällä PBKDF2-algoritmia, jolle käytetään
HMAC-ratkaisua (Hash-based Message Authentication Code) ja tausta-algoritmina
SHA2-algoritmia (myös SHA1 on toteutettu, mutta sitä ei käytetä koodissa).

Testauksesta löytyy lisää tietoa testausdokumentista.

# Lähteet
* [FIPS PUB 46-3: Data Encryption Standard](
    http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf)
* [NIST Special Publication 800-67 Revision 2: Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher](
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf)
* [FIPS PUB 197: Advanced Encryption Standard (AES)](
    https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
* [FIPS PUB 180-4: Secure Hash Standard (SHS)](
    http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
* [Descriptions of SHA-256, SHA-384, and SHA-512 (Archived)](
    https://web.archive.org/web/20130526224224/http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf)
* [Block cipher mode of operation - Wikipedia](
    https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
* [PKCS Padding Method - IBM z/OS Cryptographic Services](
    https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.2.0/com.ibm.zos.v2r2.csfb400/pkcspad.htm)
* [System.nanoTime (Java Platform SE 8)](
    https://docs.oracle.com/javase/8/docs/api/java/lang/System.html#nanoTime%28%29)
