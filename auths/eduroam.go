package auths

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

func Eduroam(login, password string) uint8 {

	formData := url.Values{}
	formData.Set("login", login)
	formData.Set("password", password)

	response, err := http.PostForm("https://eduroam.ustc.edu.cn/cgi-bin/eduroam-test.cgi", formData)
	if err != nil {
		return 3
	}
	defer response.Body.Close()

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return 3
	}
	bodyStr := string(bodyBytes)

	if strings.Contains(bodyStr, "EAP Failure") {
		return 1
	} else if strings.Contains(bodyStr, "illegal") {
		return 2
	} else if strings.Contains(bodyStr, "EAP Success") {
		return 0
	} else {
		return 3
	}
}
