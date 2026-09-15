#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
一键发布：扫描 downloads 成品 -> 校验 -> 自动更新 index.html 与 sha256.txt -> 提交并推送。

用法（双击 一键发布.bat 即可，无需手动传参）：
    python publish_release.py              # 完整流程（含提交+推送）
    python publish_release.py --skip-push  # 只更新本地文件并提交，不推送
    python publish_release.py --strict     # 未过加壳检查则中止（默认只警告）

设计要点：
  - 只认 downloads/ 下的成品，完全不依赖任何构建目录
  - index.html 一律按二进制读写+定点正则替换，绝不整体重写，行尾/BOM 不会被动
  - 支持三种投放形式：已打包 zip / 同名目录 / 裸 exe（后两者自动打包）
"""
import os
import re
import sys
import glob
import time
import zipfile
import hashlib
import argparse
import subprocess
import datetime

# ---------- 控制台编码自适应（cmd 是 GBK，VS Code 终端是 UTF-8）----------
def _setup_console():
    enc = None
    if os.name == 'nt':
        try:
            import ctypes
            cp = ctypes.windll.kernel32.GetConsoleOutputCP()
            # 936 = 简体中文 GBK 控制台；其余（含被重定向/无控制台的 0）按 UTF-8 处理
            enc = 'gbk' if cp == 936 else 'utf-8'
        except Exception:
            enc = 'gbk'
    if enc:
        try:
            sys.stdout.reconfigure(encoding=enc, errors='replace')
            sys.stderr.reconfigure(encoding=enc, errors='replace')
        except Exception:
            pass

_setup_console()

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
DOWNLOADS = os.path.join(ROOT, 'downloads')
INDEX_HTML = os.path.join(ROOT, 'index.html')
SHA_TXT = os.path.join(DOWNLOADS, 'sha256.txt')

VARIANTS = [
    {'key': '标准版', 'zip': '智能交易系统_标准版.zip', 'sha_id': 'sha-standard', 'btn': '下载标准版'},
    {'key': '专业版', 'zip': '智能交易系统_专业版.zip', 'sha_id': 'sha-pro', 'btn': '下载专业版'},
]

GIT_IDENTITY = ['-c', 'user.name=jiaokai-jj',
                '-c', 'user.email=jiaokai-jj@users.noreply.github.com']


def log(msg=''):
    print(msg, flush=True)


def hr(title=None):
    log('=' * 62)
    if title:
        log('  ' + title)
        log('=' * 62)


# ---------- 定位 git ----------
def _ver_of(p):
    m = re.search(r'app-(\d+)\.(\d+)\.(\d+)', p)
    return tuple(map(int, m.groups())) if m else (0, 0, 0)


def find_git():
    try:
        r = subprocess.run(['git', '--version'], capture_output=True, timeout=20)
        if r.returncode == 0:
            return ['git']
    except Exception:
        pass
    base = os.environ.get('LOCALAPPDATA', '')
    if not base:
        return None
    pats = []
    for tail in (r'resources\app\git\cmd\git.exe', r'resources\app\git\mingw64\bin\git.exe'):
        pats += glob.glob(os.path.join(base, 'GitHubDesktop', 'app-*', tail))
    if not pats:
        return None
    pats.sort(key=_ver_of, reverse=True)
    return [pats[0]]


# ---------- 工具 ----------
def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.digest().hex()


def mb(nbytes, nd=1):
    return round(nbytes / 1024.0 / 1024.0, nd)


# 常规 PE 区段：出现非常规区段通常意味着 VMP 加壳
STD_SEC = {'.text', '.rdata', '.data', '.rsrc', '.reloc', '.pdata', '.tls',
           '.bss', '.edata', '.idata', '.CRT', '.fptable', '.ndata'}


def pe_sections(data):
    """粗略提取 PE 区段名，失败返回 None。"""
    try:
        if data[:2] != b'MZ':
            return None
        e_lfanew = int.from_bytes(data[0x3C:0x40], 'little')
        if data[e_lfanew:e_lfanew + 4] != b'PE\0\0':
            return None
        coff = e_lfanew + 4
        nsec = int.from_bytes(data[coff + 2:coff + 4], 'little')
        opt_size = int.from_bytes(data[coff + 16:coff + 18], 'little')
        sect_off = coff + 20 + opt_size
        out = []
        for i in range(nsec):
            off = sect_off + i * 40
            name = data[off:off + 8].rstrip(b'\0')
            try:
                out.append(name.decode('ascii', 'replace'))
            except Exception:
                out.append('?')
        return out
    except Exception:
        return None


def looks_packed(exe_bytes):
    secs = pe_sections(exe_bytes)
    if secs is None:
        return None  # 无法判定
    weird = [s for s in secs if s not in STD_SEC and not s.startswith('/')]
    return len(weird) > 0


# ---------- 发现成品 ----------
def locate(v):
    """返回 (zip_path, 是否需要现打)"""
    stem = v['zip'][:-4]  # 智能交易系统_标准版
    zip_path = os.path.join(DOWNLOADS, v['zip'])

    # 1) 已打包 zip
    if os.path.isfile(zip_path):
        return zip_path, False
    # 2) 同名目录，内含 exe
    d = os.path.join(DOWNLOADS, stem)
    if os.path.isdir(d):
        exes = [os.path.join(d, f) for f in os.listdir(d)
                if f.lower().endswith('.exe')]
        if exes:
            return (zip_path, True, max(exes, key=os.path.getsize), stem)
    # 3) 裸 exe
    loose = os.path.join(DOWNLOADS, stem + '.exe')
    if os.path.isfile(loose):
        return (zip_path, True, loose, stem)
    return None


def build_zip(src_exe, dirname, zip_path):
    """把 exe 打成 zip，内部布局 <dirname>/<basename>"""
    tmp = zip_path + '.tmp'
    if os.path.exists(tmp):
        os.remove(tmp)
    name = os.path.basename(src_exe)
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        z.write(src_exe, dirname + '/' + name)
    os.replace(tmp, zip_path)
    return zip_path


def zip_entry_name(info):
    """还原 zip 内的中文文件名。

    zipfile 对没有 UTF-8 标志位的条目一律按 cp437 解码，而 Windows 打包产物通常是 GBK，
    直接取 filename 会得到乱码（如 "智能交易系统" -> "╓╟─▄╜╗..."）。
    """
    n = info.filename
    if info.flag_bits & 0x800:          # 已标记 UTF-8，Python 解码正确
        return os.path.basename(n)
    for enc in ('gbk', 'utf-8'):
        try:
            return os.path.basename(n.encode('cp437').decode(enc))
        except Exception:
            continue
    return os.path.basename(n)


def inspect_zip(zpath):
    with zipfile.ZipFile(zpath) as z:
        bad = z.testzip()
        if bad is not None:
            raise RuntimeError('压缩包损坏: %s' % bad)
        items = z.infolist()
        exes = [i for i in items if i.filename.lower().endswith('.exe')]
        if not exes:
            raise RuntimeError('包内没有找到 exe: %s' % os.path.basename(zpath))
        main = max(exes, key=lambda i: i.file_size)
        with z.open(main) as f:
            head = f.read(8192)   # 判断 PE 区段只需头部若干 KB
    return {'exe_name': zip_entry_name(main),
            'exe_size': main.file_size, 'head': head}


# ---------- 更新 index.html（二进制定点替换）----------
def patch_index(results):
    with open(INDEX_HTML, 'rb') as f:
        raw = f.read()
    before = raw
    notes = []

    for v, r in zip(VARIANTS, results):
        # 1) SHA256
        pat = re.compile(
            rb'(<code id="' + v['sha_id'].encode('ascii') + rb'"[^>]*>)([0-9a-fA-F]+)(</code>)')
        new, n = pat.subn(lambda m: m.group(1) + r['sha256'].encode('ascii') + m.group(3), raw)
        if n:
            raw = new
            notes.append('%s SHA256 已更新' % v['key'])
        else:
            notes.append('%s SHA256 未找到锚点(跳过)' % v['key'])

        # 2) 按钮体积文案
        pat2 = re.compile(
            v['btn'].encode('utf-8') + r' \(约([0-9.]+)MB\)'.encode('utf-8'))
        new2, n2 = pat2.subn(
            v['btn'].encode('utf-8') + (' (约%dMB)' % round(r['zip_mb'])).encode('utf-8'), raw)
        if n2:
            raw = new2
            notes.append('%s 体积文案 -> 约%dMB' % (v['key'], round(r['zip_mb'])))

    # 3) 使用说明里的 exe 文件名
    exe_names = ' / '.join(r['exe_name'] for r in results)
    want = ('<li>双击运行对应版本的 exe（%s）</li>' % exe_names).encode('utf-8')
    pat3 = re.compile(r'<li>双击运行(.*?)</li>'.encode('utf-8'))
    if pat3.search(raw):
        raw = pat3.sub(want, raw, count=1)
        notes.append('说明文案已同步: %s' % exe_names)

    if raw == before:
        log('  index.html 无需修改')
        return False
    with open(INDEX_HTML, 'wb') as f:
        f.write(raw)
    for x in notes:
        log('  · ' + x)
    return True


def write_sha_txt(results):
    nl = '\r\n'
    if os.path.exists(SHA_TXT):
        with open(SHA_TXT, 'rb') as f:
            old = f.read()
        nl = '\r\n' if b'\r\n' in old else '\n'
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = ['# 智能交易系统 下载包校验值',
             '# 生成时间 ' + now,
             '# 校验方式：Windows 终端执行  certutil -hashfile "文件名" SHA256',
             '']
    for v, r in zip(VARIANTS, results):
        lines += [v['zip'],
                  'SHA256: ' + r['sha256'],
                  '大小  : %.1f MB (exe 约 %.1f MB)' % (r['zip_mb'], r['exe_mb']),
                  '']
    with open(SHA_TXT, 'wb') as f:
        f.write(('\n'.join(lines) + '\n').replace('\n', nl).encode('utf-8'))
    log('  sha256.txt 已重写')


# ---------- git ----------
def git(gitcmd, args, check=True, timeout=300):
    cmd = gitcmd + GIT_IDENTITY + args
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=timeout)
    out = (p.stdout or b'').decode('utf-8', 'replace') + (p.stderr or b'').decode('utf-8', 'replace')
    if check and p.returncode != 0:
        raise RuntimeError('git %s 失败 (code=%d)\n%s' % (args[0], p.returncode, out.strip()))
    return p.returncode, out.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--skip-push', action='store_true')
    ap.add_argument('--strict', action='store_true')
    args = ap.parse_args()

    hr('一键发布：%s' % datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    if not os.path.isdir(DOWNLOADS):
        log('[错误] 找不到 downloads 目录: %s' % DOWNLOADS)
        return 1

    gitcmd = find_git()
    if not gitcmd:
        log('[错误] 找不到可用的 git（本机未装 Git 且未找到 GitHub Desktop 内置 git）')
        return 1
    log('git: %s' % gitcmd[0])

    # ---------- 扫描并准备成品 ----------
    results = []
    for v in VARIANTS:
        got = locate(v)
        if not got:
            log('[提示] 未发现 %s 成品，跳过' % v['key'])
            continue
        zip_path = got[0]
        if got[1]:
            src_exe, stem = got[2], got[3]
            log('[%s] 发现 exe，自动打包 -> %s' % (v['key'], v['zip']))
            build_zip(src_exe, stem, zip_path)

        info = inspect_zip(zip_path)
        r = {'key': v['key'], 'zip': v['zip'], 'path': zip_path,
             'sha256': sha256_of(zip_path),
             'zip_size': os.path.getsize(zip_path),
             'exe_name': info['exe_name'], 'exe_size': info['exe_size'],
             'head': info['head']}
        r['zip_mb'] = mb(r['zip_size'])
        r['exe_mb'] = mb(r['exe_size'])
        results.append(r)
        packed = looks_packed(info['head'])
        flag = '已加壳' if packed else ('未加壳?' if packed is False else '加壳状态未知')
        log('[%s] %s | %.1fMB | exe %.1fMB | %s'
            % (v['key'], r['sha256'][:16] + '...', r['zip_mb'], r['exe_mb'], flag))
        if packed is False:
            log('     ！警告：' + v['key'] + ' 的 exe 未见加壳特征区段')
    if not results:
        log('\n[结束] downloads 里没有可发布的成品。')
        return 1

    if any(looks_packed(r['head']) is False for r in results) and args.strict:
        log('\n[中止] --strict 模式：存在疑似未加壳的 exe。')
        return 1

    # ---------- 更新文件 ----------
    log('\n[1/3] 更新 index.html ...')
    idx_changed = patch_index(results)
    write_sha_txt(results)

    # ---------- 提交 ----------
    log('\n[2/3] 提交 ...')
    add_targets = [INDEX_HTML, SHA_TXT]
    for r in results:
        add_targets.append(r['path'])
    try:
        git(gitcmd, ['add', '--'] + add_targets)
    except RuntimeError as e:
        log('[错误] ' + str(e))
        return 1

    _, st = git(gitcmd, ['status', '--porcelain'], check=False)
    staged = [l for l in st.splitlines() if l[:1] in ('M', 'A')]
    if not staged:
        log('  没有任何变更，跳过提交与推送。')
        hr('完成（无变更）')
        return 0

    title = '发布更新: ' + ' / '.join('%s %.0fMB' % (r['key'], round(r['zip_mb'])) for r in results)
    body = '\n'.join('- %s: SHA256 %s (%.1fMB, exe %.1fMB)' % (r['key'], r['sha256'], r['zip_mb'], r['exe_mb'])
                     for r in results)
    msg = title + '\n\n' + body + '\n'
    try:
        git(gitcmd, ['commit', '-m', msg])
        log('  ' + title)
    except RuntimeError as e:
        log('[错误] 提交失败: ' + str(e))
        return 1

    # ---------- 推送 ----------
    if args.skip_push:
        hr('完成（已提交，按参数未推送）')
        return 0
    log('\n[3/3] 推送 ...')
    try:
        _, out = git(gitcmd, ['push', 'origin', 'HEAD'], timeout=600)
        if out:
            log(out)
    except RuntimeError as e:
        log('[错误] 推送失败: ' + str(e))
        log('  处理办法：打开 GitHub Desktop 点 Push origin，或检查网络/登录态。')
        return 1
    hr('发布完成，Pages 约 1-3 分钟后生效：www.jyt.cc.cd')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        log('\n[异常] %s: %s' % (type(e).__name__, e))
        import traceback
        traceback.print_exc()
        sys.exit(1)
