package trace

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultMaxLogSize / DefaultLogBackups 把连接级诊断日志限制在约 48MiB。
	// traffic.json 仍只保留聚合；trace 含目标域名与客户端地址，既不能无限
	// 占盘，也不应无限延长明细留存周期。
	DefaultMaxLogSize int64 = 16 << 20
	DefaultLogBackups       = 2
)

// JSONLRecorder 把连接 trace 写入有界 JSONL 文件。
//
// 轮转完全在进程内完成，不依赖发行版是否安装/启用 logrotate。每个归档
// 最大约 maxSize，文件依次为 path.1、path.2。启动时若接手旧版留下的超大
// 文件，只保留最后 maxSize 内的完整 JSON 行，避免第一次升级仍拖着巨型归档。
type JSONLRecorder struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	size     int64
	maxSize  int64
	backups  int
	lastWarn time.Time
	closed   bool
}

func NewJSONLRecorder(path string, maxSize int64, backups int) (*JSONLRecorder, error) {
	if path == "" {
		return nil, fmt.Errorf("trace 日志路径为空")
	}
	if maxSize <= 0 {
		maxSize = DefaultMaxLogSize
	}
	if backups < 0 {
		backups = 0
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := rotateOversizedAtStartup(path, maxSize, backups); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &JSONLRecorder{
		path: path, f: f, size: st.Size(), maxSize: maxSize, backups: backups,
	}, nil
}

func (r *JSONLRecorder) Record(t *Trace) {
	if r == nil || t == nil {
		return
	}
	line := append(t.JSON(), '\n')

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if r.f == nil {
		if err := r.openAppendLocked(); err != nil {
			r.warnLocked(err)
			return
		}
	}
	if r.size > 0 && r.size+int64(len(line)) > r.maxSize {
		if err := r.rotateLocked(); err != nil {
			r.warnLocked(err)
			return
		}
	}
	n, err := r.f.Write(line)
	r.size += int64(n)
	if err != nil || n != len(line) {
		if err == nil {
			err = io.ErrShortWrite
		}
		r.warnLocked(err)
	}
}

func (r *JSONLRecorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	r.closed = true
	return err
}

func (r *JSONLRecorder) rotateLocked() error {
	closeErr := r.f.Close()
	r.f = nil
	if closeErr != nil {
		_ = r.openAppendLocked()
		return closeErr
	}
	if err := rotateArchives(r.path, r.backups); err != nil {
		// 轮转失败不能让 recorder 永久失声；尽量重新接回当前文件，
		// 后续每条记录仍会重试轮转并受一分钟告警限频保护。
		_ = r.openAppendLocked()
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = r.openAppendLocked()
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

func (r *JSONLRecorder) openAppendLocked() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f = f
	r.size = st.Size()
	return nil
}

func (r *JSONLRecorder) warnLocked(err error) {
	now := time.Now()
	if r.lastWarn.IsZero() || now.Sub(r.lastWarn) >= time.Minute {
		log.Printf("警告: trace 日志写入/轮转失败: %v", err)
		r.lastWarn = now
	}
}

func rotateArchives(path string, backups int) error {
	if backups <= 0 {
		return os.Remove(path)
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", path, backups))
	for i := backups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", path, i)
		dst := fmt.Sprintf("%s.%d", path, i+1)
		if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(path, path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func rotateOversizedAtStartup(path string, maxSize int64, backups int) error {
	st, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Size() < maxSize {
		return nil
	}
	if backups <= 0 {
		return os.Remove(path)
	}

	// 先生成只含完整行的尾部副本；成功前绝不动原文件。
	tail := path + ".tail"
	if err := copyTailLines(path, tail, maxSize); err != nil {
		_ = os.Remove(tail)
		return err
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", path, backups))
	for i := backups - 1; i >= 1; i-- {
		if err := os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1)); err != nil && !os.IsNotExist(err) {
			_ = os.Remove(tail)
			return err
		}
	}
	if err := os.Rename(tail, path+".1"); err != nil {
		return err
	}
	return os.Remove(path)
}

func copyTailLines(srcPath, dstPath string, maxSize int64) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return err
	}
	start := st.Size() - maxSize
	if start < 0 {
		start = 0
	}
	if _, err := src.Seek(start, io.SeekStart); err != nil {
		return err
	}
	br := bufio.NewReader(src)
	if start > 0 {
		// 丢弃 seek 落到的半行，确保归档从完整 JSON 开始。
		if _, err := br.ReadBytes('\n'); err != nil && err != io.EOF {
			return err
		}
	}
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dst, br)
	closeErr := dst.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
