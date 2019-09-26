#ifndef TEST_BREAK_SSRP_H
#define TEST_BREAK_SSRP_H
/*
 * test_break_ssrp.h
 */

/*
 * taken from
 * https://en.wikipedia.org/wiki/List_of_the_most_common_passwords#SplashData
 */
static const char *passwords[] = {
	"!@#$%^&*",
	"000000",
	"111111",
	"121212",
	"123123",
	"1234",
	"12345",
	"123456",
	"1234567",
	"12345678",
	"123456789",
	"1234567890",
	"1qaz2wsx",
	"654321",
	"666666",
	"696969",
	"Football",
	"aa123456",
	"abc123",
	"access",
	"admin",
	"adobe123",
	"ashley",
	"azerty",
	"bailey",
	"baseball",
	"batman",
	"charlie",
	"donald",
	"dragon",
	"flower",
	"football",
	"freedom",
	"hello",
	"hottie",
	"iloveyou",
	"jesus",
	"letmein",
	"login",
	"loveme",
	"master",
	"michael",
	"monkey",
	"mustang",
	"ninja",
	"passw0rd",
	"password",
	"password1",
	"photoshop",
	"princess",
	"qazwsx",
	"qwerty",
	"qwerty123",
	"qwertyuiop",
	"shadow",
	"solo",
	"starwars",
	"sunshine",
	"superman",
	"trustno1",
	"welcome",
	"whatever",
	"zaq1zaq1",
};

static const size_t passwordslen = sizeof(passwords) / sizeof(*passwords);

#endif /* ndef TEST_BREAK_SSRP_H */
