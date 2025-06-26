package auths

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"

	"github.com/Dainsleif233/Edu-Auth/utils"
	"github.com/Dainsleif233/ddddGocr"
)

//go:embed assets/ujs/*
var assetFS embed.FS

type htmlResult struct {
	Lt, PwdDefaultEncryptSalt, Execution string
}

type captchaResponse struct {
	BigImageNum, SmallImageNum, YHeight int
	SmallImage, BigImage                string
}

type signResponse struct {
	Code          int
	Message, Sign string
}

func getHtml(client *http.Client) (*htmlResult, error) {

	url := "https://pass.ujs.edu.cn/cas/login"
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	bodyStr := string(bodyBytes)

	//name="lt" value="xxx"/>
	//id="pwdDefaultEncryptSalt" value="xxx"/>
	//name="execution" value="xxx"/>
	ltRegex := regexp.MustCompile(`name="lt" value="(.*?)"/>`)
	saltRegex := regexp.MustCompile(`id="pwdDefaultEncryptSalt" value="(.*?)"/>`)
	executionRegex := regexp.MustCompile(`name="execution" value="(.*?)"/>`)
	lts := ltRegex.FindStringSubmatch(bodyStr)
	salts := saltRegex.FindStringSubmatch(bodyStr)
	execution := executionRegex.FindStringSubmatch(bodyStr)
	if len(lts) < 1 || len(salts) < 1 {
		return nil, errors.New("htmlMatch error")
	}
	return &htmlResult{
		Lt:                    lts[1],
		PwdDefaultEncryptSalt: salts[1],
		Execution:             execution[1],
	}, nil
}

func needCaptcha(client *http.Client, login string) (bool, error) {

	url := "https://pass.ujs.edu.cn/cas/needCaptcha.html?pwdEncrypt2=pwdEncryptSalt&_=" + utils.GetTimestamp(13).TimestampStr + "&username=" + login
	response, err := client.Get(url)
	if err != nil {
		return true, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return true, err
	}
	bodyStr := string(bodyBytes)
	if bodyStr == "true" {
		return true, nil
	} else {
		return false, nil
	}
}

func getSign(client *http.Client) (string, error) {

	imgs := [10]string{"0.png", "1.png", "2.png", "3.png", "4.png", "5.png", "6.png", "7.png", "8.png", "9.png"}

	var sign string
	for range 5 {
		url1 := "https://pass.ujs.edu.cn/cas/sliderCaptcha.do?_=" + utils.GetTimestamp(13).TimestampStr
		response, err := client.Get(url1)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		var resp captchaResponse
		if err = json.NewDecoder(response.Body).Decode(&resp); err != nil {
			return "", err
		}
		bigImage, err := base64.StdEncoding.DecodeString(resp.BigImage)
		if err != nil {
			return "", err
		}
		bigImageNum := resp.BigImageNum
		bgImage, err := assetFS.ReadFile("assets/ujs/" + imgs[bigImageNum])
		if err != nil {
			return "", err
		}
		result, err := ddddGocr.SlideMatchWithByte(bigImage, bgImage, "comparison", "default")
		if err != nil {
			return "", err
		}

		url2 := "https://pass.ujs.edu.cn/cas/verifySliderImageCode.do?canvasLength=590&moveLength=" + strconv.Itoa(result.X1)
		response2, err := client.Get(url2)
		if err != nil {
			return "", err
		}
		defer response2.Body.Close()
		var resp2 signResponse
		if err := json.NewDecoder(response2.Body).Decode(&resp2); err != nil {
			return "", err
		}
		if resp2.Code == 0 {
			sign = resp2.Sign
			return sign, nil
		}
	}

	return "", errors.New("getSign error")
}

func encryptPwd(pwd, salt string) (string, error) {

	chars := "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

	prefix, err := utils.RandomStr(chars, 64)
	if err != nil {
		return "", err
	}
	iv, err := utils.RandomStr(chars, 16)
	if err != nil {
		return "", err
	}

	encrypted, err := utils.AesCbcEncrypt(prefix+pwd, salt, iv)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func Ujs(login, password string) uint8 {

	jar, err := cookiejar.New(nil)
	if err != nil {
		return 3
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	formData := url.Values{}
	formData.Set("username", login)
	formData.Set("dllt", "userNamePasswordLogin")
	formData.Set("_eventId", "submit")
	formData.Set("rmShown", "1")
	formData.Set("sign", "")
	htmlResult, err := getHtml(client)
	if err != nil {
		return 3
	}
	formData.Set("lt", htmlResult.Lt)
	formData.Set("execution", htmlResult.Execution)

	passwordEncrypt, err := encryptPwd(password, htmlResult.PwdDefaultEncryptSalt)
	if err != nil {
		return 3
	}
	formData.Set("password", passwordEncrypt)

	needCaptcha, err := needCaptcha(client, login)
	if err != nil {
		return 3
	}
	if needCaptcha {
		sign, err := getSign(client)
		formData.Set("sign", sign)
		if err != nil {
			return 3
		}
	}

	url := "https://pass.ujs.edu.cn/cas/login"
	response, err := client.PostForm(url, formData)
	if err != nil {
		return 3
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusFound && response.Header.Get("Location") == "https://pass.ujs.edu.cn/cas/index.do" {
		return 0
	}

	return 1
}
