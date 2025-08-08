package finding

type Severity string

const (
	Info    Severity = "INFO"
	Warning Severity = "WARN"
	Error   Severity = "ERROR"
)

type Finding struct {
	File     string
	Severity Severity
	Message  string
}
