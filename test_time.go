package main
import (
    fmt
    time
)
func main() {
    tokensExpiresAt := 2026-02-27T02:41:18.692816+00:00
    exp, err := time.Parse(time.RFC3339, tokensExpiresAt)
    if err != nil {
        fmt.Println(Error:, err)
    } else {
        fmt.Println(Parsed:, exp)
        fmt.Println(Time
