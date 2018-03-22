#ifndef TEST_BREAK_PLAINTEXT_H
#define TEST_BREAK_PLAINTEXT_H
/*
 * test_break_plaintext.h
 */

/* part of the first chapter of Alice's Adventures in Wonderland,
   by Lewis Carroll. Taken from https://www.gutenberg.org/files/11/11-0.txt */
static const char *english_text = /* about 2k letters */
	"Alice was beginning to get very tired of sitting by her sister on the"
	" bank, and of having nothing to do: once or twice she had peeped into"
	" the book her sister was reading, but it had no pictures or"
	" conversations in it, ‘and what is the use of a book,’ thought Alice"
	" ‘without pictures or conversations?’"

	"So she was considering in her own mind (as well as she could, for the"
	" hot day made her feel very sleepy and stupid), whether the pleasure of"
	" making a daisy-chain would be worth the trouble of getting up and"
	" picking the daisies, when suddenly a White Rabbit with pink eyes ran"
	" close by her."

	"There was nothing so VERY remarkable in that; nor did Alice think it so"
	" VERY much out of the way to hear the Rabbit say to itself, ‘Oh dear! Oh"
	" dear! I shall be late!’ (when she thought it over afterwards, it"
	" occurred to her that she ought to have wondered at this, but at the"
	" time it all seemed quite natural); but when the Rabbit actually TOOK A"
	" WATCH OUT OF ITS WAISTCOAT-POCKET, and looked at it, and then hurried"
	" on, Alice started to her feet, for it flashed across her mind that she"
	" had never before seen a rabbit with either a waistcoat-pocket, or a"
	" watch to take out of it, and burning with curiosity, she ran across the"
	" field after it, and fortunately was just in time to see it pop down a"
	" large rabbit-hole under the hedge.  "

	"In another moment down went Alice after it, never once considering how"
	" in the world she was to get out again."

	"The rabbit-hole went straight on like a tunnel for some way, and then"
	" dipped suddenly down, so suddenly that Alice had not a moment to think"
	" about stopping herself before she found herself falling down a very"
	" deep well."

	"Either the well was very deep, or she fell very slowly, for she had"
	" plenty of time as she went down to look about her and to wonder what"
	" was going to happen next. First, she tried to look down and make out"
	" what she was coming to, but it was too dark to see anything; then she"
	" looked at the sides of the well, and noticed that they were filled with"
	" cupboards and book-shelves; here and there she saw maps and pictures"
	" hung upon pegs. She took down a jar from one of the shelves as she"
	" passed; it was labelled ‘ORANGE MARMALADE’, but to her great"
	" disappointment it was empty: she did not like to drop the jar for fear"
	" of killing somebody, so managed to put it into one of the cupboards as"
	" she fell past it.";


/* part of the first chapter of Faust, by Johann Wolfgang von Goethe.
   Taken from https://www.gutenberg.org/files/21000/21000-0.txt */
static const char *german_text = /* about 2k letters */
	"Ihr naht euch wieder, schwankende Gestalten!"
	" Die früh sich einst dem trüben Blick gezeigt."
	" Versuch’ ich wohl euch diesmal fest zu halten?"
	" Fühl’ ich mein Herz noch jenem Wahn geneigt?"
	" Ihr drängt euch zu! nun gut, so mögt ihr walten,"
	" Wie ihr aus Dunst und Nebel um mich steigt;"
	" Mein Busen fühlt sich jugendlich erschüttert"
	" Vom Zauberhauch der euren Zug umwittert."

	"Ihr bringt mit euch die Bilder froher Tage,"
	" Und manche liebe Schatten steigen auf;"
	" Gleich einer alten, halbverklungnen Sage,"
	" Kommt erste Lieb’ und Freundschaft mit herauf;"
	" Der Schmerz wird neu, es wiederholt die Klage"
	" Des Lebens labyrinthisch irren Lauf,"
	" Und nennt die Guten, die, um schöne Stunden"
	" Vom Glück getäuscht, vor mir hinweggeschwunden."

	"Sie hören nicht die folgenden Gesänge,"
	" Die Seelen, denen ich die ersten sang,"
	" Zerstoben ist das freundliche Gedränge,"
	" Verklungen ach! der erste Wiederklang."
	" Mein Leid[Lied] ertönt der unbekannten Menge,"
	" Ihr Beyfall selbst macht meinem Herzen bang,"
	" Und was sich sonst an meinem Lied erfreuet,"
	" Wenn es noch lebt, irrt in der Welt zerstreuet."

	"Und mich ergreift ein längst entwöhntes Sehnen"
	" Nach jenem stillen, ernsten Geisterreich,"
	" Es schwebet nun, in unbestimmten Tönen,"
	" Mein lispelnd Lied, der Aeolsharfe gleich,"
	" Ein Schauer faßt mich, Thräne folgt den Thränen,"
	" Das strenge Herz es fühlt sich mild und weich;"
	" Was ich besitze seh’ ich wie im weiten,"
	" Und was verschwand wird mir zu Wirklichkeiten."

	"_Vorspiel_"

	"_auf dem Theater._"

	"_Director, Theaterdichter,"
	"lustige Person._"

	"_Director._"

	"Ihr beyden die ihr mir so oft,"
	" In Noth und Trübsal, beygestanden,"
	" Sagt was ihr wohl, in deutschen Landen,"
	" Von unsrer Unternehmung hofft?"
	" Ich wünschte sehr der Menge zu behagen,"
	" Besonders weil sie lebt und leben läßt."
	" Die Pfosten sind, die Breter aufgeschlagen,"
	" Und jedermann erwartet sich ein Fest."
	" Sie sitzen schon, mit hohen Augenbraunen,"
	" Gelassen da und möchten gern erstaunen."
	" Ich weiß wie man den Geist des Volks versöhnt;"
	" Doch so verlegen bin ich nie gewesen;"
	" Zwar sind sie an das Beste nicht gewöhnt,"
	" Allein sie haben schrecklich viel gelesen."
	" Wie machen wir’s? daß alles frisch und neu"
	" Und mit Bedeutung auch gefällig sey."
	" Denn freylich mag ich gern die Menge sehen,"
	"Wenn sich der Strom nach unsrer Bude drängt,"
	"Und mit gewaltig wiederholten Wehen,"
	"Sich durch die enge Gnadenpforte zwängt;"
	"Bey hellem Tage, schon vor Vieren,"
	"Mit Stößen sich bis an die Kasse ficht"
	"Und, wie in Hungersnoth um Brot an Beckerthüren,"
	"Um ein Billet sich fast die Hälse bricht."
	"Dieß Wunder wirkt auf so verschiedne Leute"
	"Der Dichter nur; mein Freund, o! thu es heute.";


/* dd of=/dev/stdout if=/dev/urandom bs=1 count=2048 | base64 */
static const char *random_base64 =
"GDwNqDm8HrEmRTs6HR1qABpPLy/B3XOOy5JDN0/zJRF2mr57Td5QW469tsDlcSetB1jek69JglIZ"
"DJcmMfFoJZY+iqyuOYCiybGHWlv/MHsfnpmREx2pGY1kMR6NhxYSIc7615jnAsXBgNOQzYV6nGqz"
"frNeHLOE2xXciYu3y6IVES0n3o6o+zou6ocBui+jK/vA7xLwUBW7jtum5r8TOvqnPmRIN5GwNIar"
"vU4BySGy6/xGcFAOeqHFBnMKoo8a2X8/sg7KqV1gW3xegKR7sHEds6oMTh46HRdzDar0uPJT3JUf"
"6fmb1bMTBC76Nhs0dnzebWJXhTR2PcOEoFM77uOaH8HnnQ10m1kprtKGdYTX3rQzGeyh8HCW7rMe"
"Cdxlu5+q95NHJsvIHx/lIT991GACiwXQgUH0eD7S5FDK7rYcE3D9Q0wmo+6SBsDmf0O494QIqpqS"
"yT4oa1bA7AhpiKINrfGjZ3qccQtq3oI689OM74U/RXcCsuq4gxQM6z7iquP7WjUUlqAcVKA4rQmv"
"3p/4MNqpByaITXobqN93SKC7iob5SY0oKeU+lPP8rKSAgOyVep3wJvVxPIxqUkmffk16w88kOM/Z"
"MjLhwEAtr8lIMnFymLYwYYxE4PoS/+Y6Jz02ZygSjli6/tF3wy2NmLFnkwg8jg+25doL/lDomfXY"
"rLLXnjIlvYXEBZVvnFUSNPoEBu2aj2u/JoKOO6sWgLlAui9xJK5F9sNN5UNFXkSgyF280Tm6km3g"
"LlV28ZzJhO1bZi7hs2SJAoJ9g9tPdni1+Tayn2dM/thqhl3WFUxsAz7pOfLpRvHrvHeoSNAq3kvw"
"puh7S4zOJF6gRk3yVIz77kAyOCRQ6dbLHH1fWPkHJoUsP0AF3i3BQmNH2B7hr0tp7vF2BWjVbvu0"
"A9tfBhhymv1z+3nLzZY7hPXgiT9kow5ybbj0SDFqnul3YGTMX3RdyHG+iN/1gPlXns3Tf4BJZYIj"
"PalX8tIFqENE9Z8n4K4YXtsyRewod+XZvGYO0dpXEoaRUptTslkSc4yqs5b0wEVuuXiWcSBnHOqX"
"XxqOvQTQKt5YUDat0I52SquusR3WTBi6VCT16a91cC1a5eOa68I6q21mNQBQVRlDsJM+/ia9N+nB"
"Mv4uH1U1rVmGbBuSJYay5hjc0otnpERvnjFV+rLcRdPv4Im8IqRQGg/Xwr8rNexfu+7xepqT8ycX"
"slZ3F19vLLgTGIFGuPdlmGf8T9iKz7FPIso45ELwOkT8/4LAF+JfOQoYqutL3EKz/AWk14iOHXyU"
"sVFrMW439KV1XaU5Do8lfzpOt9nlgW80/zQ1fNuHKl/S/ue1JN9gpyEalafBpKTY1WACCTPNYi6Y"
"Xe3znaj60L3UZd2zkIG3vmPVlZW768PkobFZ6zxWeYQGUcmmH8nJRxqpzBQ292v52llHRAEdjzvD"
"NoOQRquMPnco5auEJj57OBHMzgVvFzJOrGe6KjHtqJSLA97Ivcz2igsJm7silg2TEBevrUjy4qEg"
"smR95tAkJD50+mgpEYoaKJ6bVV1S6mfn5NMm33oR6quUgDdL/VTcgT5BELbK/gdgteq8naHrSw4C"
"ODxKgFiH+gBKg97LaZ1cdj8ypKIeq0oA3TCeq135/TnCx9ftqDghfx4+ersTRbihHx8NuXBgESj7"
"lTGv00TJjI74ZBwSBizh1I6MxjdEKfTxMtF9oMbJZJKhF2rrwFSTzQXp1dK9MMfA87RZ/8HX/+Xm"
"V58TZZY97yroH2ai85hTUvt7Mr5epbQtl+5dDhjcDLOji5OuiHb+EPF+LvRDB3T2U9DUsUwwAk9J"
"UCsccXErahFYTbYwm9jloXcF0QxlMuiWudSM4bP3agF+aCX1JXSQWfvXeufHz/ndAUgM7pblGLoz"
"h+c0+fTrAXmKYHaOZ4eFveRqMYgpwwM3dOdqjpio7ufoM+v9BYYNkJwL3SP1Vij/r/AOvAR8vHpC"
"Y6x+KQlE/sYsSkNFFRAEvnUBSlg4uafsqM03w8fOCAG/+XHLrJKDLmT4guzlVIuTdUkP8tRrGrjL"
"7Wrooacu7Ky02VnDkvA0mTYYUPhLfVvkxDmIEv0tPvORKtMGpsICA/sdrB77Vnog7t84/dVYSMjd"
"49mGdwkfJot8PpgkwXUozl3fbb2g0P6QpBLrQ7YPOJnO5c/fFEM1BejFEllpyve5y72jH/zTPY0q"
"Ij+CBAkHTvImi+TRVvSr7hAHoJ0c6MZHRyGWi8weYQrkbYqSQAUTdanm6rL38851m3BU1+wlGjHP"
"QJ+37xc2VKGy6nDc1981E/s0xdvjc3aV8wY2TInCg1QfmFX1g7fDp4x9nzT7Ukv1vToKJdC2HuCu"
"IZWUWy4oULcwn0YLjQxkZoUgQBR+YrcUkZfSlDmdNcWLm5TU32r/dnFm3cLQFLtQG8m1NvqBN8kb"
"ZS1sVwO3Pw3bLSQ2TDiIenPE2ibb4PaS1Wl9uittz09ytIf+uuKIewI/j2TvRiHKY/Ec/AjwdFGI"
"ZW9NJDY05fA9mHggwfWHPj45JzMRBKEFRMuXPR35n0+3IgpqS5qxjiBz+HVpCqVDWy7S7ISRBkDt"
"WIn70zUWxEibmF/5wOFGi+kfAHNY6FGxBK68Eu4CNSz3JdLECOj6CYxHXDwWW3Bn1kWG4kf4Wtfb"
"PIHK2hl5etNJZbnrR32rrb8s+880G+DUJx9/FAXBd83s2FXzRWQmDglatpypJ901cnoCR8Y=";

#endif /* ndef TEST_BREAK_PLAINTEXT_H */
