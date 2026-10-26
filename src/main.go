package main

// script-tasks(脚本定时任务): fnOS 定时任务应用后端 v1.2.0
// 任务类型: script(.sh/.py 文件) / command(任意命令) / http(定时 HTTP 请求)
// 调度: 标准 cron 5 段, 或 6 段(含秒); 图形化周期在前端生成 5 段表达式
// 执行语义: 失败重试、超时终止、防重叠、成功后链式运行下一个任务
// 实时输出: 日志文件即缓冲, 前端轮询日志接口; 停止: 取消上下文杀进程组
// 数据目录: 环境变量 ST_DATA_DIR; 端口: ST_PORT(默认 18788); socket: ST_SOCK

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- TLS(仅 TCP 直连模式用): 复用飞牛为自定义域名自动续签的证书 ----------
// 飞牛桌面走 HTTPS 时, http 内嵌页会被浏览器按混合内容拦掉, 所以 TCP 模式必须说 HTTPS。
// 证书来源: ST_CERT_DIR (默认飞牛证书目录), 域名由 ST_CERT_DOMAIN 指定(未指定则不用 TLS);
// 取最新子目录里的 <域名>.crt/.key; 每次握手时检查指纹, 变了就重新加载 —— 自动跟上续签。
// 注: fnOS 同源网关(socket)模式下 TLS 由飞牛网关终结, 不走这里。

var (
	certMu      sync.Mutex
	certCache   *tls.Certificate
	certCacheFP string
)

func certFiles() (string, string, bool) {
	base := os.Getenv("ST_CERT_DIR")
	dom := os.Getenv("ST_CERT_DOMAIN")
	if dom == "" {
		return "", "", false
	}
	if base == "" {
		base = filepath.Join("/usr/trim/var/trim_connect/ssls", dom)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return "", "", false
	}
	var newest string
	var newestT time.Time
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newestT) {
			newestT = info.ModTime()
			newest = e.Name()
		}
	}
	if newest == "" {
		return "", "", false
	}
	crt := filepath.Join(base, newest, dom+".crt")
	key := filepath.Join(base, newest, dom+".key")
	if _, err := os.Stat(crt); err != nil {
		return "", "", false
	}
	if _, err := os.Stat(key); err != nil {
		return "", "", false
	}
	return crt, key, true
}

func getCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	crt, key, ok := certFiles()
	if !ok {
		return nil, fmt.Errorf("no cert available")
	}
	fp := crt + "|" + key
	if st, err := os.Stat(crt); err == nil {
		fp += "|" + strconv.FormatInt(st.ModTime().Unix(), 10)
	}
	certMu.Lock()
	defer certMu.Unlock()
	if certCache != nil && certCacheFP == fp {
		return certCache, nil
	}
	c, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		if certCache != nil {
			return certCache, nil
		}
		return nil, err
	}
	certCache = &c
	certCacheFP = fp
	return certCache, nil
}

//go:embed ui/index.html
var indexHTML []byte

var (
	dataDir     string
	scriptsDir  string
	logsDir     string
	backupsDir  string
	stateFile   string
	runsFile    string
	settingFile string
)

const (
	TypeScript  = "script"
	TypeCommand = "command"
	TypeHTTP    = "http"
)

type Task struct {
	ID        string `json:"id"`
	Name      string `json:"name"` // script=文件名; command/http=显示名
	Type      string `json:"type"` // "" 视为 script(兼容旧数据)
	Remark    string `json:"remark"`
	Enabled   bool   `json:"enabled"`
	Cron      string `json:"cron"`
	CreatedAt int64  `json:"createdAt"` // unix ms
	LastRunAt int64  `json:"lastRunAt"` // unix ms, 0=从未
	LastExit  int    `json:"lastExit"`  // -999=从未运行
	Running   bool   `json:"running"`
	// command 型
	Command string `json:"command"`
	// http 型
	Method  string `json:"method"`
	URL     string `json:"url"`
	Headers string `json:"headers"` // 每行 Key: Value
	Body    string `json:"body"`
	// 高级设置
	Retry         int    `json:"retry"`         // 失败后重试次数 0..5
	RetryInterval int    `json:"retryInterval"` // 重试间隔(秒)
	TimeoutSec    int    `json:"timeoutSec"`    // 0=不限(内部上限 6h)
	NextTaskID    string `json:"nextTaskId"`    // 成功后接着运行的任务
}

func (t *Task) taskType() string {
	if t.Type == TypeCommand || t.Type == TypeHTTP {
		return t.Type
	}
	return TypeScript
}

type Run struct {
	ID       string `json:"id"`
	TaskID   string `json:"taskId"`
	Name     string `json:"name"`
	Trigger  string `json:"trigger"` // schedule | manual | chain
	StartAt  int64  `json:"startAt"`
	EndAt    int64  `json:"endAt"` // 0=运行中
	ExitCode int    `json:"exitCode"`
	Log      string `json:"log"` // 日志文件名
}

type Settings struct {
	LogKeepDays int `json:"logKeepDays"` // 日志保留天数, 超期文件自动删
}

var settings = Settings{LogKeepDays: 30}

var (
	mu       sync.Mutex
	tasks    []*Task
	runs     []*Run
	firedSec = map[string]string{} // taskID -> 已触发的秒键, 防重复
	cronCach = map[string]*cronExpr{}
	loc      = time.Local
)

func nowMs() int64 { return time.Now().UnixMilli() }

func saveState() {
	b, _ := json.MarshalIndent(tasks, "", "  ")
	os.WriteFile(stateFile, b, 0644)
	rb, _ := json.MarshalIndent(runs, "", "  ")
	os.WriteFile(runsFile, rb, 0644)
}

func saveSettings() {
	b, _ := json.MarshalIndent(settings, "", "  ")
	os.WriteFile(settingFile, b, 0644)
}

func loadState() {
	if b, err := os.ReadFile(stateFile); err == nil {
		json.Unmarshal(b, &tasks)
	}
	if b, err := os.ReadFile(runsFile); err == nil {
		json.Unmarshal(b, &runs)
	}
	if b, err := os.ReadFile(settingFile); err == nil {
		json.Unmarshal(b, &settings)
	}
	if settings.LogKeepDays < 1 {
		settings.LogKeepDays = 30
	}
	if tasks == nil {
		tasks = []*Task{}
	}
	if runs == nil {
		runs = []*Run{}
	}
	for _, t := range tasks {
		t.Running = false
	}
}

func findTask(id string) *Task {
	for _, t := range tasks {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// ---------- cron 解析 (5段: 分 时 日 月 周; 6段: 秒 分 时 日 月 周) ----------

type cronField struct {
	set map[int]bool
}

var monthNames = map[string]int{"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6, "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12}
var dowNames = map[string]int{"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6}

func fieldValue(s string, names map[string]int) (int, error) {
	if names != nil {
		if v, ok := names[strings.ToUpper(s)]; ok {
			return v, nil
		}
	}
	return strconv.Atoi(s)
}

func parseField(s string, min, max int, names map[string]int) (*cronField, error) {
	f := &cronField{set: map[int]bool{}}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("空字段")
		}
		step := 1
		base := part
		if i := strings.Index(part, "/"); i >= 0 {
			base = part[:i]
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n < 1 {
				return nil, fmt.Errorf("步长无效: %s", part)
			}
			step = n
		}
		var lo, hi int
		if base == "*" {
			lo, hi = min, max
		} else if j := strings.Index(base, "-"); j >= 0 {
			a, e1 := fieldValue(base[:j], names)
			b, e2 := fieldValue(base[j+1:], names)
			if e1 != nil || e2 != nil {
				return nil, fmt.Errorf("范围无效: %s", part)
			}
			lo, hi = a, b
		} else {
			a, err := fieldValue(base, names)
			if err != nil {
				return nil, fmt.Errorf("数值无效: %s", part)
			}
			lo, hi = a, a
			if step != 1 { // 形如 5/10 视为从5开始到max
				hi = max
			}
		}
		if lo < min || hi > max || lo > hi {
			return nil, fmt.Errorf("超出范围: %s", part)
		}
		for v := lo; v <= hi; v += step {
			f.set[v] = true
		}
	}
	return f, nil
}

type cronExpr struct {
	sec, min, hour, dom, mon, dow *cronField
	domStar, dowStar              bool
	hasSec                        bool
}

func parseCron(expr string) (*cronExpr, error) {
	parts := strings.Fields(expr)
	c := &cronExpr{}
	var err error
	secStr := "0"
	if len(parts) == 6 {
		c.hasSec = true
		secStr = parts[0]
		parts = parts[1:]
	} else if len(parts) != 5 {
		return nil, fmt.Errorf("cron 需要 5 段 (分 时 日 月 周) 或 6 段 (秒 分 时 日 月 周)")
	}
	if c.sec, err = parseField(secStr, 0, 59, nil); err != nil {
		return nil, err
	}
	if c.min, err = parseField(parts[0], 0, 59, nil); err != nil {
		return nil, err
	}
	if c.hour, err = parseField(parts[1], 0, 23, nil); err != nil {
		return nil, err
	}
	if c.dom, err = parseField(parts[2], 1, 31, nil); err != nil {
		return nil, err
	}
	if c.mon, err = parseField(parts[3], 1, 12, monthNames); err != nil {
		return nil, err
	}
	if c.dow, err = parseField(parts[4], 0, 7, dowNames); err != nil {
		return nil, err
	}
	if c.dow.set[0] {
		c.dow.set[7] = true
	}
	if c.dow.set[7] {
		c.dow.set[0] = true
	}
	c.domStar = parts[2] == "*"
	c.dowStar = parts[4] == "*"
	return c, nil
}

// 编译结果缓存(调度器每秒调用, 避免反复解析)
// 注意: 必须用独立锁 —— taskView/scheduler 都在持有 mu 时调用它, 共用 mu 会自死锁
var cronMu sync.Mutex

func compileCron(expr string) (*cronExpr, error) {
	cronMu.Lock()
	ce, ok := cronCach[expr]
	cronMu.Unlock()
	if ok {
		return ce, nil
	}
	ce, err := parseCron(expr)
	if err != nil {
		return nil, err
	}
	cronMu.Lock()
	if len(cronCach) > 512 {
		cronCach = map[string]*cronExpr{}
	}
	cronCach[expr] = ce
	cronMu.Unlock()
	return ce, nil
}

func (c *cronExpr) matchDay(t time.Time) bool {
	domOK := c.dom.set[t.Day()]
	dowOK := c.dow.set[int(t.Weekday())]
	// 标准 cron 语义: 日与周都受限时取或, 否则取与
	if !c.domStar && !c.dowStar {
		return domOK || dowOK
	}
	return domOK && dowOK
}

func (c *cronExpr) match(t time.Time) bool {
	return c.sec.set[t.Second()] && c.min.set[t.Minute()] && c.hour.set[t.Hour()] &&
		c.mon.set[int(t.Month())] && c.matchDay(t)
}

// nextAfter 返回 from 之后(严格大于 from 所在秒)下一次触发时间; 找不到返回零值
// 用单位跳跃代替逐秒扫描, 保证 2月29日 这类稀疏表达式也快速返回
func (c *cronExpr) nextAfter(from time.Time) time.Time {
	t := from.Truncate(time.Second).Add(time.Second)
	limit := from.Add(4 * 366 * 24 * time.Hour)
	for t.Before(limit) {
		if !c.mon.set[int(t.Month())] {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, loc)
			continue
		}
		if !c.matchDay(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, loc)
			continue
		}
		if !c.hour.set[t.Hour()] {
			t = t.Truncate(time.Hour).Add(time.Hour)
			continue
		}
		if !c.min.set[t.Minute()] {
			t = t.Truncate(time.Minute).Add(time.Minute)
			continue
		}
		if !c.sec.set[t.Second()] {
			t = t.Add(time.Second)
			continue
		}
		return t
	}
	return time.Time{}
}

// ---------- 任务运行 ----------

const maxRunTimeout = 6 * time.Hour

// 正在运行的 run 的控制句柄(用于停止)
type runControl struct {
	cancel  context.CancelFunc
	stopped atomic.Bool
}

var runControls = sync.Map{} // runID -> *runControl

func startRun(t *Task, trigger string) *Run {
	return startRunChain(t, trigger, map[string]bool{t.ID: true})
}

// chain 记录本次链式调用已经过的任务, 防 A→B→A 死循环
func startRunChain(t *Task, trigger string, chain map[string]bool) *Run {
	mu.Lock()
	if findTask(t.ID) != t {
		// 任务列表已被导入替换, 旧指针的任务已不存在, 不再启动(防导入中途调度的旧任务)
		mu.Unlock()
		return nil
	}
	if t.Running {
		mu.Unlock()
		return nil
	}
	t.Running = true
	r := &Run{
		ID:      fmt.Sprintf("%d", nowMs()),
		TaskID:  t.ID,
		Name:    t.Name,
		Trigger: trigger,
		StartAt: nowMs(),
	}
	r.Log = fmt.Sprintf("%s-%s.log", t.ID, time.Now().Format("20060102150405"))
	runs = append([]*Run{r}, runs...)
	if len(runs) > 200 {
		runs = runs[:200]
	}
	saveState()
	mu.Unlock()

	go executeRun(t, r, chain)
	return r
}

func executeRun(t *Task, r *Run, chain map[string]bool) {
	logPath := filepath.Join(logsDir, r.Log)
	lf, err := os.Create(logPath)
	if err != nil {
		finishRun(t, r, -2)
		return
	}
	defer lf.Close()
	trigName := map[string]string{"schedule": "定时", "manual": "手动", "chain": "链式"}[r.Trigger]
	fmt.Fprintf(lf, "[%s] 开始运行 %s (触发: %s)\n", time.Now().Format("2006-01-02 15:04:05"), t.Name, trigName)

	ctx, cancel := context.WithCancel(context.Background())
	ctl := &runControl{cancel: cancel}
	runControls.Store(r.ID, ctl)
	defer runControls.Delete(r.ID)
	defer cancel()

	attempts := 1 + t.Retry
	exit := -2
	for i := 0; i < attempts; i++ {
		if i > 0 {
			iv := t.RetryInterval
			if iv < 1 {
				iv = 30
			}
			fmt.Fprintf(lf, "[重试] 上次退出码 %d, %d 秒后进行第 %d 次重试\n", exit, iv, i)
			select {
			case <-ctx.Done():
				exit = -3
				fmt.Fprintf(lf, "[已停止] 等待重试时被手动停止\n")
				i = attempts // 结束循环
			case <-time.After(time.Duration(iv) * time.Second):
			}
			if exit == -3 {
				break
			}
		}
		if attempts > 1 {
			fmt.Fprintf(lf, "[尝试 %d/%d]\n", i+1, attempts)
		}
		exit = runOnce(t, lf, ctx, ctl)
		if exit == 0 || ctl.stopped.Load() {
			break
		}
	}
	fmt.Fprintf(lf, "[%s] 结束, 退出码 %d\n", time.Now().Format("2006-01-02 15:04:05"), exit)
	finishRun(t, r, exit)

	// 成功后链式运行下一个任务(不受对方启用开关影响; 已在链中的跳过防循环)
	if exit == 0 && t.NextTaskID != "" && !ctl.stopped.Load() {
		mu.Lock()
		next := findTask(t.NextTaskID)
		mu.Unlock()
		if next != nil && !chain[next.ID] {
			chain[next.ID] = true
			startRunChain(next, "chain", chain)
		}
	}
}

// runOnce 执行一次尝试, 返回退出码: 0 成功; >0 进程退出码/HTTP 失败;
// -1 超时; -2 启动错误; -3 被手动停止
func runOnce(t *Task, lf *os.File, parent context.Context, ctl *runControl) int {
	timeout := maxRunTimeout
	if t.TimeoutSec > 0 && time.Duration(t.TimeoutSec)*time.Second < timeout {
		timeout = time.Duration(t.TimeoutSec) * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	switch t.taskType() {
	case TypeHTTP:
		return runHTTP(t, lf, ctx, ctl)
	case TypeCommand:
		fmt.Fprintf(lf, "[命令] %s\n", t.Command)
		cmd := exec.CommandContext(ctx, "/bin/bash", "-c", t.Command)
		return runCmd(t, cmd, lf, ctx, ctl)
	default: // script
		scriptPath := filepath.Join(scriptsDir, t.Name)
		interp, ierr := interpreterFor(t.Name)
		if ierr != nil {
			fmt.Fprintf(lf, "[错误] %v, 无法运行 .py 脚本\n", ierr)
			return -2
		}
		fmt.Fprintf(lf, "[解释器] %s %s\n", interp, t.Name)
		cmd := exec.CommandContext(ctx, interp, scriptPath)
		return runCmd(t, cmd, lf, ctx, ctl)
	}
}

func runCmd(t *Task, cmd *exec.Cmd, lf *os.File, ctx context.Context, ctl *runControl) int {
	cmd.Dir = scriptsDir
	cmd.Env = append(os.Environ(),
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TASK_NAME="+t.Name,
	)
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 3 * time.Second
	runErr := cmd.Run()
	if runErr == nil {
		return 0
	}
	if ctl.stopped.Load() {
		fmt.Fprintf(lf, "\n[已停止] 被手动停止\n")
		return -3
	}
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(lf, "\n[超时] 已超过设定时长, 进程被终止\n")
		return -1
	}
	if ee, ok := runErr.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	fmt.Fprintf(lf, "\n[错误] %v\n", runErr)
	return -2
}

func runHTTP(t *Task, lf *os.File, ctx context.Context, ctl *runControl) int {
	method := strings.ToUpper(strings.TrimSpace(t.Method))
	if method == "" {
		method = "GET"
	}
	var bodyReader io.Reader
	if t.Body != "" && method != "GET" && method != "HEAD" {
		bodyReader = strings.NewReader(t.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.URL, bodyReader)
	if err != nil {
		fmt.Fprintf(lf, "[错误] 请求构建失败: %v\n", err)
		return -2
	}
	for _, line := range strings.Split(t.Headers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.Index(line, ":"); i > 0 {
			req.Header.Set(strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]))
		}
	}
	fmt.Fprintf(lf, "[请求] %s %s\n", method, t.URL)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		if ctl.stopped.Load() {
			fmt.Fprintf(lf, "[已停止] 被手动停止\n")
			return -3
		}
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Fprintf(lf, "[超时] 请求超过设定时长\n")
			return -1
		}
		fmt.Fprintf(lf, "[错误] 请求失败: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	fmt.Fprintf(lf, "[响应] %s\n", resp.Status)
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if len(data) > 0 {
		lf.Write(data)
		if len(data) >= 64*1024 {
			fmt.Fprintf(lf, "\n[注] 响应内容超过 64KB, 已截断\n")
		} else if data[len(data)-1] != '\n' {
			lf.WriteString("\n")
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return 0
	}
	fmt.Fprintf(lf, "[失败] HTTP 状态码 %d 不在 2xx 范围\n", resp.StatusCode)
	return 1
}

func finishRun(t *Task, r *Run, exit int) {
	mu.Lock()
	defer mu.Unlock()
	r.EndAt = nowMs()
	r.ExitCode = exit
	t.Running = false
	t.LastRunAt = r.StartAt
	t.LastExit = exit
	saveState()
	cleanupLogs(t.ID)
}

// 日志清理: 每任务最多保留 30 个文件 + 超过保留天数的全删
func cleanupLogs(taskID string) {
	entries, err := os.ReadDir(logsDir)
	if err != nil {
		return
	}
	var mine []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), taskID+"-") {
			mine = append(mine, e.Name())
		}
	}
	sort.Strings(mine)
	for len(mine) > 30 {
		os.Remove(filepath.Join(logsDir, mine[0]))
		mine = mine[1:]
	}
}

func pruneOldLogs() {
	days := settings.LogKeepDays
	if days < 1 {
		return
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	entries, err := os.ReadDir(logsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(logsDir, e.Name()))
		}
	}
}

// ---------- 调度器 ----------

func scheduler() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	pruneTick := 0
	for now := range tick.C {
		key := now.Format("20060102150405")
		cur := now.Truncate(time.Second)
		mu.Lock()
		var due []*Task
		for _, t := range tasks {
			if !t.Enabled || t.Running {
				continue
			}
			ce, err := compileCron(t.Cron)
			if err != nil {
				continue
			}
			if ce.match(cur) && firedSec[t.ID] != key {
				firedSec[t.ID] = key
				due = append(due, t)
			}
		}
		mu.Unlock()
		for _, t := range due {
			startRun(t, "schedule")
		}
		pruneTick++
		if pruneTick >= 6*3600 { // 每 6 小时清一次超期日志
			pruneTick = 0
			pruneOldLogs()
		}
	}
}

// ---------- HTTP API ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func taskView(t *Task) map[string]any {
	m := map[string]any{
		"id": t.ID, "name": t.Name, "type": t.taskType(), "remark": t.Remark, "enabled": t.Enabled,
		"cron": t.Cron, "createdAt": t.CreatedAt, "lastRunAt": t.LastRunAt,
		"lastExit": t.LastExit, "running": t.Running, "nextRun": int64(0),
		"command": t.Command, "method": t.Method, "url": t.URL, "headers": t.Headers, "body": t.Body,
		"retry": t.Retry, "retryInterval": t.RetryInterval, "timeoutSec": t.TimeoutSec,
		"nextTaskId": t.NextTaskID,
	}
	if t.Enabled {
		if ce, err := compileCron(t.Cron); err == nil {
			if nx := ce.nextAfter(time.Now()); !nx.IsZero() {
				m["nextRun"] = nx.UnixMilli()
			}
		}
	}
	return m
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.(sh|py)$`)

// ensureExt 补默认后缀 .sh (已有 .sh/.py 则不动)
func ensureExt(n string) string {
	if strings.HasSuffix(n, ".sh") || strings.HasSuffix(n, ".py") {
		return n
	}
	return n + ".sh"
}

// interpreterFor 按后缀选解释器
func interpreterFor(name string) (string, error) {
	if strings.HasSuffix(name, ".py") {
		if p, err := exec.LookPath("python3"); err == nil {
			return p, nil
		}
		if _, err := os.Stat("/usr/bin/python3"); err == nil {
			return "/usr/bin/python3", nil
		}
		return "", fmt.Errorf("未找到 python3")
	}
	return "/bin/bash", nil
}

func validName(n string) bool {
	return nameRe.MatchString(n) && !strings.Contains(n, "..")
}

// command/http 任务的显示名: 非空、无换行、≤80 字符
func validLabel(n string) bool {
	return n != "" && len([]rune(n)) <= 80 && !strings.ContainsAny(n, "\r\n")
}

func validHTTPMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH":
		return true
	}
	return false
}

func validHTTPURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

// 校验高级设置字段, 返回错误信息(空=通过)
func validAdvanced(retry, retryInterval, timeoutSec int) string {
	if retry < 0 || retry > 5 {
		return "重试次数需在 0..5 之间"
	}
	if retryInterval < 1 || retryInterval > 3600 {
		return "重试间隔需在 1..3600 秒之间"
	}
	if timeoutSec < 0 || timeoutSec > 86400 {
		return "超时需在 0..86400 秒之间 (0=不限)"
	}
	return ""
}

func nameTaken(name, excludeID string) bool {
	for _, x := range tasks {
		if x.ID != excludeID && x.Name == name {
			return true
		}
	}
	return false
}

func handleTasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		defer mu.Unlock()
		out := []map[string]any{}
		for _, t := range tasks {
			out = append(out, taskView(t))
		}
		writeJSON(w, 200, out)
	case http.MethodPost: // 新建
		var body struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Content string `json:"content"`
			Command string `json:"command"`
			Method  string `json:"method"`
			URL     string `json:"url"`
			Headers string `json:"headers"`
			Body    string `json:"body"`
			Remark  string `json:"remark"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&body); err != nil {
			errJSON(w, 400, "请求格式错误")
			return
		}
		typ := body.Type
		if typ == "" {
			typ = TypeScript
		}
		t := &Task{ID: fmt.Sprintf("%d", nowMs()), Type: typ, Remark: body.Remark,
			Enabled: false, Cron: "0 3 * * *", CreatedAt: nowMs(), LastExit: -999,
			RetryInterval: 30}
		mu.Lock()
		defer mu.Unlock()
		switch typ {
		case TypeScript:
			name := ensureExt(strings.TrimSpace(body.Name))
			if !validName(name) {
				errJSON(w, 400, "文件名只能含字母/数字/./_/- 且以 .sh 或 .py 结尾")
				return
			}
			if nameTaken(name, "") {
				errJSON(w, 409, "同名脚本已存在")
				return
			}
			if err := os.WriteFile(filepath.Join(scriptsDir, name), []byte(body.Content), 0755); err != nil {
				errJSON(w, 500, "写入失败: "+err.Error())
				return
			}
			t.Name = name
		case TypeCommand:
			name := strings.TrimSpace(body.Name)
			if !validLabel(name) {
				errJSON(w, 400, "任务名称不能为空且不超过 80 字")
				return
			}
			if strings.TrimSpace(body.Command) == "" {
				errJSON(w, 400, "命令不能为空")
				return
			}
			if nameTaken(name, "") {
				errJSON(w, 409, "同名任务已存在")
				return
			}
			t.Name = name
			t.Command = body.Command
		case TypeHTTP:
			name := strings.TrimSpace(body.Name)
			if !validLabel(name) {
				errJSON(w, 400, "任务名称不能为空且不超过 80 字")
				return
			}
			if !validHTTPMethod(body.Method) {
				errJSON(w, 400, "HTTP 方法无效")
				return
			}
			if !validHTTPURL(strings.TrimSpace(body.URL)) {
				errJSON(w, 400, "URL 需以 http:// 或 https:// 开头")
				return
			}
			if nameTaken(name, "") {
				errJSON(w, 409, "同名任务已存在")
				return
			}
			t.Name = name
			t.Method = strings.ToUpper(body.Method)
			t.URL = strings.TrimSpace(body.URL)
			t.Headers = body.Headers
			t.Body = body.Body
		default:
			errJSON(w, 400, "未知任务类型")
			return
		}
		tasks = append(tasks, t)
		saveState()
		writeJSON(w, 200, taskView(t))
	default:
		errJSON(w, 405, "method not allowed")
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, 405, "method not allowed")
		return
	}
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		errJSON(w, 400, "上传解析失败")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		errJSON(w, 400, "没有文件")
		return
	}
	defer file.Close()
	name := filepath.Base(hdr.Filename)
	if !validName(name) {
		errJSON(w, 400, "文件名只能含字母/数字/./_/- 且以 .sh 或 .py 结尾")
		return
	}
	content, err := io.ReadAll(io.LimitReader(file, 2<<20))
	if err != nil {
		errJSON(w, 500, "读取失败")
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if nameTaken(name, "") {
		errJSON(w, 409, "同名脚本已存在")
		return
	}
	if err := os.WriteFile(filepath.Join(scriptsDir, name), content, 0755); err != nil {
		errJSON(w, 500, "写入失败: "+err.Error())
		return
	}
	t := &Task{ID: fmt.Sprintf("%d", nowMs()), Name: name, Type: TypeScript, Enabled: false,
		Cron: "0 3 * * *", CreatedAt: nowMs(), LastExit: -999, RetryInterval: 30}
	tasks = append(tasks, t)
	saveState()
	writeJSON(w, 200, taskView(t))
}

// /api/tasks/{id}/... 与 /api/tasks/{id}
func handleTask(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	mu.Lock()
	t := findTask(id)
	mu.Unlock()
	if t == nil {
		errJSON(w, 404, "任务不存在")
		return
	}
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	switch {
	case sub == "" && r.Method == http.MethodPut:
		var body struct {
			Name          *string `json:"name"`
			Remark        *string `json:"remark"`
			Enabled       *bool   `json:"enabled"`
			Cron          *string `json:"cron"`
			Command       *string `json:"command"`
			Method        *string `json:"method"`
			URL           *string `json:"url"`
			Headers       *string `json:"headers"`
			Body          *string `json:"body"`
			Retry         *int    `json:"retry"`
			RetryInterval *int    `json:"retryInterval"`
			TimeoutSec    *int    `json:"timeoutSec"`
			NextTaskID    *string `json:"nextTaskId"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, 400, "请求格式错误")
			return
		}
		if body.Cron != nil {
			if _, err := parseCron(*body.Cron); err != nil {
				errJSON(w, 400, "cron 表达式无效: "+err.Error())
				return
			}
		}
		ri, rint, to := t.Retry, t.RetryInterval, t.TimeoutSec
		if body.Retry != nil {
			ri = *body.Retry
		}
		if body.RetryInterval != nil {
			rint = *body.RetryInterval
		}
		if body.TimeoutSec != nil {
			to = *body.TimeoutSec
		}
		if msg := validAdvanced(ri, rint, to); msg != "" {
			errJSON(w, 400, msg)
			return
		}
		mu.Lock()
		if body.NextTaskID != nil && *body.NextTaskID != "" {
			if *body.NextTaskID == t.ID {
				mu.Unlock()
				errJSON(w, 400, "不能选择自己作为后续任务")
				return
			}
			if findTask(*body.NextTaskID) == nil {
				mu.Unlock()
				errJSON(w, 400, "后续任务不存在")
				return
			}
		}
		if body.Name != nil {
			raw := strings.TrimSpace(*body.Name)
			if t.taskType() == TypeScript {
				newName := ensureExt(raw)
				if !validName(newName) {
					mu.Unlock()
					errJSON(w, 400, "文件名只能含字母/数字/./_/- 且以 .sh 或 .py 结尾")
					return
				}
				if newName != t.Name {
					if t.Running {
						mu.Unlock()
						errJSON(w, 409, "任务正在运行中, 不能改名")
						return
					}
					if nameTaken(newName, t.ID) {
						mu.Unlock()
						errJSON(w, 409, "同名脚本已存在")
						return
					}
					if err := os.Rename(filepath.Join(scriptsDir, t.Name), filepath.Join(scriptsDir, newName)); err != nil {
						mu.Unlock()
						errJSON(w, 500, "改名失败: "+err.Error())
						return
					}
					t.Name = newName
				}
			} else {
				if !validLabel(raw) {
					mu.Unlock()
					errJSON(w, 400, "任务名称不能为空且不超过 80 字")
					return
				}
				if raw != t.Name && nameTaken(raw, t.ID) {
					mu.Unlock()
					errJSON(w, 409, "同名任务已存在")
					return
				}
				t.Name = raw
			}
		}
		if body.Remark != nil {
			t.Remark = *body.Remark
		}
		if body.Enabled != nil {
			t.Enabled = *body.Enabled
		}
		if body.Cron != nil {
			t.Cron = *body.Cron
		}
		if body.Command != nil {
			if strings.TrimSpace(*body.Command) == "" {
				mu.Unlock()
				errJSON(w, 400, "命令不能为空")
				return
			}
			t.Command = *body.Command
		}
		if body.Method != nil {
			if !validHTTPMethod(*body.Method) {
				mu.Unlock()
				errJSON(w, 400, "HTTP 方法无效")
				return
			}
			t.Method = strings.ToUpper(*body.Method)
		}
		if body.URL != nil {
			if !validHTTPURL(strings.TrimSpace(*body.URL)) {
				mu.Unlock()
				errJSON(w, 400, "URL 需以 http:// 或 https:// 开头")
				return
			}
			t.URL = strings.TrimSpace(*body.URL)
		}
		if body.Headers != nil {
			t.Headers = *body.Headers
		}
		if body.Body != nil {
			t.Body = *body.Body
		}
		t.Retry = ri
		t.RetryInterval = rint
		t.TimeoutSec = to
		if body.NextTaskID != nil {
			t.NextTaskID = *body.NextTaskID
		}
		saveState()
		v := taskView(t)
		mu.Unlock()
		writeJSON(w, 200, v)
	case sub == "" && r.Method == http.MethodDelete:
		mu.Lock()
		defer mu.Unlock()
		if t.Running {
			errJSON(w, 409, "任务正在运行中, 不能删除")
			return
		}
		if t.taskType() == TypeScript {
			os.Remove(filepath.Join(scriptsDir, t.Name))
		}
		for i, x := range tasks {
			if x.ID == id {
				tasks = append(tasks[:i], tasks[i+1:]...)
				break
			}
		}
		// 解除指向本任务的链式引用
		for _, x := range tasks {
			if x.NextTaskID == id {
				x.NextTaskID = ""
			}
		}
		saveState()
		writeJSON(w, 200, map[string]bool{"ok": true})
	case sub == "content" && r.Method == http.MethodGet:
		if t.taskType() != TypeScript {
			errJSON(w, 400, "只有脚本任务有文件内容")
			return
		}
		b, err := os.ReadFile(filepath.Join(scriptsDir, t.Name))
		if err != nil {
			errJSON(w, 404, "脚本文件不存在")
			return
		}
		writeJSON(w, 200, map[string]string{"content": string(b)})
	case sub == "content" && r.Method == http.MethodPut:
		if t.taskType() != TypeScript {
			errJSON(w, 400, "只有脚本任务有文件内容")
			return
		}
		var body struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&body); err != nil {
			errJSON(w, 400, "请求格式错误")
			return
		}
		if err := os.WriteFile(filepath.Join(scriptsDir, t.Name), []byte(body.Content), 0755); err != nil {
			errJSON(w, 500, "写入失败")
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	case sub == "run" && r.Method == http.MethodPost:
		run := startRun(t, "manual")
		if run == nil {
			errJSON(w, 409, "任务正在运行中")
			return
		}
		writeJSON(w, 200, map[string]string{"runId": run.ID})
	default:
		errJSON(w, 404, "not found")
	}
}

func handleRuns(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("taskId")
	mu.Lock()
	defer mu.Unlock()
	out := []*Run{}
	for _, run := range runs {
		if taskID == "" || run.TaskID == taskID {
			out = append(out, run)
		}
	}
	writeJSON(w, 200, out)
}

// /api/runs/{id}/log 与 /api/runs/{id}/stop
func handleRun(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/runs/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	mu.Lock()
	var target *Run
	for _, run := range runs {
		if run.ID == id {
			target = run
			break
		}
	}
	mu.Unlock()
	if target == nil {
		errJSON(w, 404, "运行记录不存在")
		return
	}
	switch {
	case sub == "log" && r.Method == http.MethodGet:
		b, err := os.ReadFile(filepath.Join(logsDir, target.Log))
		if err != nil {
			errJSON(w, 404, "日志文件不存在(可能已被自动清理)")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	case sub == "stop" && r.Method == http.MethodPost:
		if target.EndAt != 0 {
			errJSON(w, 409, "运行已结束")
			return
		}
		v, ok := runControls.Load(id)
		if !ok {
			errJSON(w, 409, "运行已结束")
			return
		}
		ctl := v.(*runControl)
		ctl.stopped.Store(true)
		ctl.cancel()
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		errJSON(w, 404, "not found")
	}
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, 200, settings)
	case http.MethodPut:
		var body Settings
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, 400, "请求格式错误")
			return
		}
		if body.LogKeepDays < 1 || body.LogKeepDays > 3650 {
			errJSON(w, 400, "保留天数需在 1..3650 之间")
			return
		}
		mu.Lock()
		settings.LogKeepDays = body.LogKeepDays
		saveSettings()
		mu.Unlock()
		pruneOldLogs()
		writeJSON(w, 200, settings)
	default:
		errJSON(w, 405, "method not allowed")
	}
}

// ---------- 备份: 全部任务 + 设置 + 脚本文件(不含运行历史与日志) ----------
// 备份文件为单个 JSON, 导出到本地(浏览器下载)或 NAS(数据目录下 backups/),
// 导入支持本地上传与 NAS 目录选取; 导入为整包替换, 先全量校验再落盘。

func backupFileName() string {
	// 精确到毫秒: 同一秒内连点两次导出也不会互相覆盖
	return "script-tasks-backup-" + time.Now().Format("20060102-150405.000") + ".json"
}

type backupScript struct {
	Name    string `json:"name"`
	Content string `json:"content"` // base64
}

type backupFile struct {
	App            string         `json:"app"`
	Format         int            `json:"format"`
	ExportedAt     int64          `json:"exportedAt"`
	Settings       Settings       `json:"settings"`
	Tasks          []*Task        `json:"tasks"`
	Scripts        []backupScript `json:"scripts"`
	MissingScripts []string       `json:"missingScripts,omitempty"`
}

func buildBackup() *backupFile {
	mu.Lock()
	tasksCopy := make([]*Task, len(tasks))
	for i, t := range tasks {
		cp := *t
		cp.Running = false
		tasksCopy[i] = &cp
	}
	st := settings
	mu.Unlock()
	bf := &backupFile{App: "script-tasks", Format: 1, ExportedAt: nowMs(), Settings: st, Tasks: tasksCopy, Scripts: []backupScript{}}
	for _, t := range tasksCopy {
		if t.taskType() != TypeScript {
			continue
		}
		b, err := os.ReadFile(filepath.Join(scriptsDir, t.Name))
		if err != nil {
			bf.MissingScripts = append(bf.MissingScripts, t.Name)
			continue
		}
		bf.Scripts = append(bf.Scripts, backupScript{Name: t.Name, Content: base64.StdEncoding.EncodeToString(b)})
	}
	return bf
}

func validateBackup(bf *backupFile) error {
	if bf.App != "script-tasks" {
		return fmt.Errorf("不是脚本定时任务的备份文件")
	}
	if bf.Format != 1 {
		return fmt.Errorf("不支持的备份格式")
	}
	// 设置值不在此拒绝: 导入时按 loadState 的口径归一(小于 1 取 30、超上限取上限),
	// 避免可导出的备份因设置值无法导入——与高级设置数值同类问题。
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, t := range bf.Tasks {
		if t == nil || t.ID == "" {
			return fmt.Errorf("备份中有任务缺少 ID")
		}
		if ids[t.ID] {
			return fmt.Errorf("备份中有重复任务 ID")
		}
		ids[t.ID] = true
		if names[t.Name] {
			return fmt.Errorf("备份中有重名任务: %s", t.Name)
		}
		names[t.Name] = true
		switch t.taskType() {
		case TypeScript:
			if !validName(t.Name) {
				return fmt.Errorf("备份中有无效脚本名: %s", t.Name)
			}
		case TypeCommand:
			if !validLabel(t.Name) || strings.TrimSpace(t.Command) == "" {
				return fmt.Errorf("备份中有无效命令任务: %s", t.Name)
			}
		case TypeHTTP:
			if !validLabel(t.Name) || !validHTTPMethod(t.Method) || !validHTTPURL(strings.TrimSpace(t.URL)) {
				return fmt.Errorf("备份中有无效 HTTP 任务: %s", t.Name)
			}
		}
		if _, err := parseCron(t.Cron); err != nil {
			return fmt.Errorf("备份中任务 %s 的 cron 无效: %s", t.Name, err.Error())
		}
		// 高级设置数值不在此拒绝: 老版本数据可能含超界值(如重试间隔 0, 运行时与
		// 编辑表单都按 30 秒处理); 导入时统一归一到现行规则, 见 normalizeAdvanced。
	}
	for _, t := range bf.Tasks {
		if t.NextTaskID != "" && !ids[t.NextTaskID] {
			return fmt.Errorf("备份中任务 %s 的后续任务不在备份中", t.Name)
		}
	}
	for _, s := range bf.Scripts {
		if !validName(s.Name) {
			return fmt.Errorf("备份中有无效脚本名: %s", s.Name)
		}
		// 只验 base64 可解: 总大小已由 decodeBackup 的读取上限卡住, 不再单设脚本上限,
		// 避免应用自身写出的大脚本在导入时被拒。
		if _, err := base64.StdEncoding.DecodeString(s.Content); err != nil {
			return fmt.Errorf("备份中脚本 %s 内容无效", s.Name)
		}
	}
	return nil
}

// normalizeAdvanced 把高级设置数值归一到现行规则, 返回是否改动过。
// 老版本任务可能含超界值(典型如重试间隔 0, 运行时与编辑表单都按 30 秒处理);
// 恢复时直接拒绝会让整份备份无法导入, 所以只修正数值, 不动任务结构。
func normalizeAdvanced(t *Task) bool {
	changed := false
	if t.Retry < 0 {
		t.Retry = 0
		changed = true
	}
	if t.Retry > 5 {
		t.Retry = 5
		changed = true
	}
	if t.RetryInterval < 1 {
		t.RetryInterval = 30
		changed = true
	}
	if t.RetryInterval > 3600 {
		t.RetryInterval = 3600
		changed = true
	}
	if t.TimeoutSec < 0 {
		t.TimeoutSec = 0
		changed = true
	}
	if t.TimeoutSec > 86400 {
		t.TimeoutSec = 86400
		changed = true
	}
	return changed
}

// doImport 整包替换: 调用前须持有 mu, 且已通过 validateBackup 校验。
// 脚本先写临时文件再逐个改名到位, 避免写一半时任务指向新旧混杂的内容。
// 返回归一过高级设置的任务数。
func doImport(bf *backupFile) (int, error) {
	for _, t := range tasks {
		if t.Running {
			return 0, fmt.Errorf("有任务正在运行中, 请先停止后再导入")
		}
	}
	oldScripts := map[string]bool{}
	for _, t := range tasks {
		if t.taskType() == TypeScript {
			oldScripts[t.Name] = true
		}
	}
	newNames := map[string]bool{}
	for _, s := range bf.Scripts {
		newNames[s.Name] = true
	}
	staged := []string{}
	defer func() {
		for _, p := range staged {
			os.Remove(p)
		}
	}()
	for _, s := range bf.Scripts {
		b, _ := base64.StdEncoding.DecodeString(s.Content)
		p := filepath.Join(scriptsDir, ".bak-tmp-"+s.Name)
		if err := os.WriteFile(p, b, 0755); err != nil {
			return 0, fmt.Errorf("写入脚本 %s 失败: %s", s.Name, err.Error())
		}
		staged = append(staged, p)
	}
	for _, s := range bf.Scripts {
		if err := os.Rename(filepath.Join(scriptsDir, ".bak-tmp-"+s.Name), filepath.Join(scriptsDir, s.Name)); err != nil {
			return 0, fmt.Errorf("恢复脚本 %s 失败: %s", s.Name, err.Error())
		}
	}
	for name := range oldScripts {
		if !newNames[name] {
			os.Remove(filepath.Join(scriptsDir, name))
		}
	}
	fixed := 0
	for _, t := range bf.Tasks {
		t.Running = false
		if normalizeAdvanced(t) {
			fixed++
		}
	}
	tasks = bf.Tasks
	if tasks == nil {
		tasks = []*Task{}
	}
	settings = bf.Settings
	if settings.LogKeepDays < 1 {
		settings.LogKeepDays = 30
	}
	if settings.LogKeepDays > 3650 {
		settings.LogKeepDays = 3650
	}
	firedSec = map[string]string{}
	saveState()
	saveSettings()
	return fixed, nil
}

func validBackupName(n string) bool {
	return strings.HasPrefix(n, "script-tasks-backup-") && strings.HasSuffix(n, ".json") &&
		n == filepath.Base(n) && !strings.Contains(n, "..")
}

func listNASBackups() []map[string]any {
	ents, _ := os.ReadDir(backupsDir)
	out := []map[string]any{}
	for _, e := range ents {
		if e.IsDir() || !validBackupName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, map[string]any{"name": e.Name(), "size": info.Size(), "modTime": info.ModTime().UnixMilli()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["modTime"].(int64) > out[j]["modTime"].(int64) })
	return out
}

func decodeBackup(r io.Reader) (*backupFile, error) {
	var bf backupFile
	if err := json.NewDecoder(io.LimitReader(r, 128<<20)).Decode(&bf); err != nil {
		return nil, fmt.Errorf("备份文件解析失败")
	}
	if err := validateBackup(&bf); err != nil {
		return nil, err
	}
	return &bf, nil
}

func importErrCode(err error) int {
	if strings.Contains(err.Error(), "运行中") {
		return 409
	}
	return 500
}

func handleBackup(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/backup")
	rest = strings.TrimPrefix(rest, "/")
	switch rest {
	case "export": // 导出到本地(浏览器下载)
		if r.Method != http.MethodGet {
			errJSON(w, 405, "method not allowed")
			return
		}
		b, _ := json.MarshalIndent(buildBackup(), "", "  ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+backupFileName()+"\"")
		w.WriteHeader(200)
		w.Write(b)
	case "nas": // 列出 NAS 目录备份
		if r.Method != http.MethodGet {
			errJSON(w, 405, "method not allowed")
			return
		}
		writeJSON(w, 200, map[string]any{"files": listNASBackups()})
	case "nas/export": // 导出到 NAS 目录(数据目录下 backups/)
		if r.Method != http.MethodPost {
			errJSON(w, 405, "method not allowed")
			return
		}
		bf := buildBackup()
		b, _ := json.MarshalIndent(bf, "", "  ")
		name := backupFileName()
		os.MkdirAll(backupsDir, 0755) // 运行中备份目录被删也能重建
		if err := os.WriteFile(filepath.Join(backupsDir, name), b, 0644); err != nil {
			errJSON(w, 500, "写入 NAS 备份失败: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"file": name, "tasks": len(bf.Tasks), "scripts": len(bf.Scripts), "missing": bf.MissingScripts})
	case "import": // 从本地上传导入
		if r.Method != http.MethodPost {
			errJSON(w, 405, "method not allowed")
			return
		}
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			errJSON(w, 400, "上传解析失败")
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			errJSON(w, 400, "没有文件")
			return
		}
		defer file.Close()
		bf, err := decodeBackup(file)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		mu.Lock()
		fixed, err := doImport(bf)
		mu.Unlock()
		if err != nil {
			errJSON(w, importErrCode(err), err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"tasks": len(bf.Tasks), "scripts": len(bf.Scripts), "fixed": fixed})
	case "nas/import": // 从 NAS 目录选取导入
		if r.Method != http.MethodPost {
			errJSON(w, 405, "method not allowed")
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || !validBackupName(body.Name) {
			errJSON(w, 400, "备份文件名无效")
			return
		}
		f, err := os.Open(filepath.Join(backupsDir, body.Name))
		if err != nil {
			errJSON(w, 404, "NAS 上没有这个备份文件")
			return
		}
		defer f.Close()
		bf, err := decodeBackup(f)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		mu.Lock()
		fixed, err := doImport(bf)
		mu.Unlock()
		if err != nil {
			errJSON(w, importErrCode(err), err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"tasks": len(bf.Tasks), "scripts": len(bf.Scripts), "fixed": fixed})
	case "nas/delete": // 删除 NAS 目录备份
		if r.Method != http.MethodPost {
			errJSON(w, 405, "method not allowed")
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || !validBackupName(body.Name) {
			errJSON(w, 400, "备份文件名无效")
			return
		}
		if err := os.Remove(filepath.Join(backupsDir, body.Name)); err != nil {
			errJSON(w, 404, "NAS 上没有这个备份文件")
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	default:
		errJSON(w, 404, "not found")
	}
}

func handleCronPreview(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	ce, err := parseCron(expr)
	if err != nil {
		errJSON(w, 400, "cron 表达式无效: "+err.Error())
		return
	}
	next := []int64{}
	from := time.Now()
	for i := 0; i < 5; i++ {
		nx := ce.nextAfter(from)
		if nx.IsZero() {
			break
		}
		next = append(next, nx.UnixMilli())
		from = nx
	}
	writeJSON(w, 200, map[string]any{"next": next})
}

// stripAppPrefix 剥掉飞牛同源网关前缀; 无尾斜杠的入口请求先重定向到
// 带斜杠形式, 保证页面里的相对路径(api/...)解析到正确位置。
func stripAppPrefix(prefix string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == prefix {
			http.Redirect(w, r, prefix+"/", http.StatusFound)
			return
		}
		if strings.HasPrefix(p, prefix+"/") {
			r2 := new(http.Request)
			*r2 = *r
			u := *r.URL
			u.Path = p[len(prefix):]
			r2.URL = &u
			h.ServeHTTP(w, r2)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func main() {
	dataDir = os.Getenv("ST_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	scriptsDir = filepath.Join(dataDir, "scripts")
	logsDir = filepath.Join(dataDir, "logs")
	backupsDir = filepath.Join(dataDir, "backups")
	stateFile = filepath.Join(dataDir, "tasks.json")
	runsFile = filepath.Join(dataDir, "runs.json")
	settingFile = filepath.Join(dataDir, "settings.json")
	os.MkdirAll(scriptsDir, 0755)
	os.MkdirAll(logsDir, 0755)
	os.MkdirAll(backupsDir, 0755)
	// 清理上次导入异常中断残留的临时脚本文件
	if ents, err := os.ReadDir(scriptsDir); err == nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".bak-tmp-") {
				os.Remove(filepath.Join(scriptsDir, e.Name()))
			}
		}
	}
	loadState()
	pruneOldLogs()

	port := os.Getenv("ST_PORT")
	if port == "" {
		port = "18788"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		// SPA 兜底: 飞牛桌面可能带路径前缀打开, 任何非 API 路径都返回页面
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(indexHTML)
	})
	mux.HandleFunc("/api/tasks", handleTasks)
	mux.HandleFunc("/api/tasks/upload", handleUpload)
	mux.HandleFunc("/api/tasks/", handleTask)
	mux.HandleFunc("/api/runs", handleRuns)
	mux.HandleFunc("/api/runs/", handleRun)
	mux.HandleFunc("/api/settings", handleSettings)
	mux.HandleFunc("/api/backup", handleBackup)
	mux.HandleFunc("/api/backup/", handleBackup)
	mux.HandleFunc("/api/cron/preview", handleCronPreview)

	go scheduler()

	srv := &http.Server{Handler: mux}
	if sock := os.Getenv("ST_SOCK"); sock != "" {
		// 飞牛同源网关把完整路径(/app/script-tasks/...)原样转给应用,
		// 前缀由应用自己剥(与飞牛原生应用一致的做法)
		srv.Handler = stripAppPrefix("/app/script-tasks", mux)
		os.Remove(sock)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Chmod(sock, 0660)
		fmt.Printf("script-tasks listening on unix socket %s, data=%s\n", sock, dataDir)
		if err := srv.Serve(ln); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	srv.Addr = "0.0.0.0:" + port
	if _, _, ok := certFiles(); ok {
		srv.TLSConfig = &tls.Config{GetCertificate: getCertificate}
		fmt.Printf("script-tasks listening on https://0.0.0.0:%s, data=%s\n", port, dataDir)
		err := srv.ListenAndServeTLS("", "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	fmt.Printf("script-tasks listening on http://0.0.0.0:%s (no cert found), data=%s\n", port, dataDir)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
