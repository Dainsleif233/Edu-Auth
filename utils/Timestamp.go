package utils

import (
	"strconv"
	"time"
)

type Timestamp struct {
	Timestamp    int64  `json:"timestamp"`
	TimestampStr string `json:"timestampStr"`
}

func GetTimestamp(lenth uint8) Timestamp {
	timestampStr := getTimestampStr(lenth)
	timestamp, _ := strconv.ParseInt(timestampStr, 10, 64)
	return Timestamp{
		Timestamp:    timestamp,
		TimestampStr: timestampStr,
	}
}

func getTimestampStr(lenth uint8) string {
	if lenth < 1 || lenth > 19 {
		return ""
	}
	timestampNano := time.Now().UnixNano()
	timestampStr := strconv.FormatInt(timestampNano, 10)
	return timestampStr[:lenth]
}
