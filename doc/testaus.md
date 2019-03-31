# Yksikkötestaus
Ohjelmassa on laajasti toteutettu JUnit-yksikkötestaus. Yksikkötestit
käsittävät testit Utils-luokan apufunktioille, täydennyskoodille,
jokaiselle kolmelle lohkotilalle, jokaiselle kolmelle algoritmille,
toteutetuille hajautusalgoritmeille sekä PBKDF2-avaimenjohtamisalgoritmin.

Yksikkötestit erinäisille algoritmeille toimivat periaatteella, jossa
tuloksen ollessa oikein muulla ei ole väliä. Tämän lisäksi myös sovelletaan
tilaan liittyviä testejä, kuten algoritmeille sen, etteivät ne suostu
salaamaan ennen alustamista.

# Nopeusmittaukset
DES- ja AES-nopeus ovat noin 1/20 ja 1/8 OpenSSL:n vastaavista.

(tarkempaa dataa ja kaaviot tulossa)
