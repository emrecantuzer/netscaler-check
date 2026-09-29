#!/bin/sh
# NetScaler / FreeBSD live triage collector, v1.0, 2026-09-29.
# Usage: /bin/sh netscaler_kernel_triage.sh --help
# Does not execute scanned content. The Perl body is passed on stdin as data.
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/netscaler
export PATH
unset ENV BASH_ENV PERL5OPT PERL5LIB PERLLIB LD_PRELOAD LD_LIBRARY_PATH LD_LIBMAP
NS_TRIAGE_SOURCE=$0
export NS_TRIAGE_SOURCE
for ns_triage_perl in /usr/bin/perl /usr/local/bin/perl /netscaler/perl; do
    if [ -x "$ns_triage_perl" ]; then
        exec "$ns_triage_perl" - "$@" <<'NS_TRIAGE_PERL'
use strict;
use warnings;
use POSIX qw(setsid WNOHANG);
use IO::Select;
use Time::HiRes qw(time sleep);
use Fcntl qw(:DEFAULT :mode);
use File::Temp qw(tempdir);
use Cwd qw(abs_path);
use Getopt::Long qw(GetOptions);

my $VERSION = '1.0';
my ($deep, $help, $selftest, $baseline, $outparent) = (0,0,0,'','/var/tmp');
my ($days, $maxseconds) = (14,0);
GetOptions('deep'=>\$deep, 'help'=>\$help, 'self-test'=>\$selftest,
    'baseline=s'=>\$baseline, 'out=s'=>\$outparent, 'days=i'=>\$days,
    'max-seconds=i'=>\$maxseconds) or die "Use --help\n";
die "Unexpected arguments: @ARGV\n" if @ARGV;
if ($help) {
    print <<'HELP';
NetScaler FreeBSD live triage v1.0 (MPX/VPX 13.1/14.1 target)
  /bin/sh netscaler_kernel_triage.sh
  /bin/sh netscaler_kernel_triage.sh --deep --days 30
  /bin/sh netscaler_kernel_triage.sh --deep --baseline /var/tmp/trusted_hashes.tsv

Run as root in the FreeBSD shell, separately on each HA node. Prefer the
secondary first, during low load. No failover is required or triggered.
Options:
  --out DIR          Existing LOCAL output parent; default /var/tmp.
  --deep             Add per-process maps, descriptors, credentials and kernel
                     stacks; expand file/log budgets. Increased CPU/disk work.
  --days N           Recent mtime/ctime review window (default 14); NOT a log
                     timestamp filter. All selected retained logs are eligible.
  --max-seconds N    Collection budget, 60..7200 (default 900, deep 1800).
  --baseline FILE    Explicitly trusted SAME BUILD/platform hashes.tsv from an
                     independent clean reference. No auto-trust of HA peer.
  --self-test        Run synthetic parser/runner tests; no appliance inspection.
  --help            Show this text without collecting anything.

Output: private ns_triage_* directory, SUMMARY.txt, findings.tsv, coverage.tsv,
command_status.tsv, hashes.tsv, baseline_compare.tsv, raw command outputs,
file_inventory.tsv, persistence.txt, log_matches.tsv, log_coverage.tsv,
process_crosscheck.tsv and evidence_sha256.tsv.
No automatic upload or archive. Copy the entire directory to your IR workstation.

Boundaries: read-only system queries, but report files and access-time/log
side effects are unavoidable. No config changes, reboot, failover, packet
capture, module load/unload, debugger, memory/core dump or remediation.
Only collector child process groups can be stopped by its timeout handler.
It does NOT prove that the running kernel or appliance is uncompromised.
FreeBSD commands do not enumerate all proprietary PPE dataplane state.
No raw process environment, private keys, master.passwd, ns.conf or full logs
are deliberately copied. Command lines, cron and matched log lines may still
contain secrets. Keep the report restricted; it is NOT automatically redacted.
HELP
    exit 0;
}
die "--days must be 1..3650\n" unless $days >= 1 && $days <= 3650;
$maxseconds ||= $deep ? 1800 : 900;
die "--max-seconds must be 60..7200\n" unless $maxseconds >= 60 && $maxseconds <= 7200;
umask 0077;
$ENV{LC_ALL} = 'C'; $ENV{LANG} = 'C'; $ENV{TZ} = 'UTC';
delete @ENV{qw(PERL5OPT PERL5LIB PERLLIB LD_PRELOAD LD_LIBRARY_PATH LD_LIBMAP)};
my ($out, $started, $deadline, $active_child) = ('',0,0,0);
my ($bytes_written, $readbytes, $hashbytes, $entry_count) = (0,0,0,0);
my $maxout = ($deep ? 256 : 128) * 1024 * 1024;
my $cmdcap = ($deep ? 8 : 4) * 1024 * 1024;
my $readcap = ($deep ? 512 : 128) * 1024 * 1024;
my $hashcap = ($deep ? 2048 : 512) * 1024 * 1024;
my $filehashcap = ($deep ? 512 : 128) * 1024 * 1024;
my $entrycap = $deep ? 100000 : 30000;
my (%fh, %status, %hashes, %hashed, %hash_queue, %seen, %inventory, %findcount);
my ($has_sha, $has_gunzip) = (eval { require Digest::SHA; 1 } ? 1:0,
                             eval { require IO::Uncompress::Gunzip; 1 } ? 1:0);

sub utc { return POSIX::strftime('%Y-%m-%dT%H:%M:%SZ', gmtime($_[0] || time)); }
sub esc {
    my $s = defined $_[0] ? "$_[0]" : '';
    $s =~ s/\\/\\\\/g;
    $s =~ s/([\x00-\x1f\x7f-\xff])/sprintf('\\x%02x',ord($1))/ge;
    return $s;
}
sub unesc {
    my $s = $_[0];
    $s =~ s/\\(\\|x[0-9a-fA-F]{2})/$1 eq '\\' ? '\\' : chr(hex(substr($1,1)))/ge;
    return $s;
}
sub emit {
    my ($name, @cols) = @_;
    my $line = join("\t", map { esc($_) } @cols)."\n";
    die "OUTPUT_BUDGET\n" if $bytes_written + length($line) > $maxout;
    print {$fh{$name}} $line or die "Report write failed: $!\n";
    $bytes_written += length($line);
}
sub coverage { emit('coverage', utc(), @_); }
sub finding {
    my ($level,$code,$evidence,$detail) = @_;
    $findcount{$level}++;
    emit('findings', $level,$code,$evidence,$detail);
}
sub guard { die "TIME_BUDGET\n" if time > $deadline; }
sub resolve {
    my ($name) = @_;
    return $name if $name =~ m{^/} && -f $name && -x $name;
    return '' if $name =~ m{/};
    for my $d (split /:/, $ENV{PATH}) { return "$d/$name" if -f "$d/$name" && -x "$d/$name"; }
    return '';
}
sub stop_child {
    return unless $active_child;
    # Child creates its own session before executing a read-only command.
    # Negative PID targets only that collector-owned session's process group.
    kill 'TERM', -$active_child;
    sleep 0.15;
    kill 'KILL', -$active_child;
    waitpid($active_child, 0);
    $active_child = 0;
}
sub run_capture {
    my ($label, $seconds, @argv) = @_;
    guard();
    my $exe = resolve($argv[0]);
    unless ($exe) {
        $status{$label} = 'MISSING';
        emit('commands',utc(),$label,'MISSING','','',join(' ',@argv));
        return '';
    }
    $argv[0] = $exe;
    my $base = "$out/raw/$label";
    open my $fo, '>', "$base.stdout" or die "$base: $!\n";
    open my $fe, '>', "$base.stderr" or die "$base: $!\n";
    pipe(my $or, my $ow) or die "pipe: $!\n";
    pipe(my $er, my $ew) or die "pipe: $!\n";
    pipe(my $ready_r, my $ready_w) or die "pipe: $!\n";
    my $t0 = time;
    my $pid = fork();
    die "fork: $!\n" unless defined $pid;
    if (!$pid) {
        $SIG{INT} = $SIG{TERM} = $SIG{ALRM} = 'DEFAULT';
        close $or; close $er; close $ready_r;
        # setsid must succeed; never run a command in the appliance shell group.
        my $sid = setsid();
        POSIX::_exit(125) unless defined($sid) && $sid >= 0;
        syswrite($ready_w, "1"); close $ready_w;
        open STDIN, '<', '/dev/null' or POSIX::_exit(125);
        open STDOUT, '>&', $ow or POSIX::_exit(125);
        open STDERR, '>&', $ew or POSIX::_exit(125);
        close $ow; close $ew;
        exec { $exe } @argv or POSIX::_exit(127);
    }
    close $ow; close $ew; close $ready_w;
    # Wait for the child's new process group to exist before allowing cleanup.
    my $ready = IO::Select->new($ready_r);
    my $ok = '';
    sysread($ready_r, $ok, 1) if $ready->can_read(2);
    close $ready_r;
    if ($ok ne '1') {
        kill 'KILL', $pid; waitpid($pid,0);
        close $or; close $er; close $fo; close $fe;
        $status{$label}='SPAWN_ERROR';
        emit('commands',utc(),$label,'SPAWN_ERROR','','',join(' ',@argv));
        return '';
    }
    $active_child = $pid;
    my $sel = IO::Select->new($or,$er);
    my $outfd = fileno($or);
    my ($nbytes,$reason,$rc) = (0,'',undef);
    while (1) {
        if (time-$t0 > $seconds || time>$deadline) { $reason='TIMEOUT'; last; }
        for my $h ($sel->can_read(0.10)) {
            my $buf = '';
            my $n = sysread($h,$buf,65536);
            if (!defined $n) { next if $!{EINTR}; $reason='READ_ERROR'; last; }
            if (!$n) { $sel->remove($h); close $h; next; }
            my $room = $cmdcap - $nbytes;
            my $totalroom = $maxout - $bytes_written - 1048576;
            $room = $totalroom if $totalroom < $room;
            my $take = $n < $room ? $n : $room;
            $take = 0 if $take < 0;
            my $dest = fileno($h) == $outfd ? $fo : $fe;
            if ($take) { print {$dest} substr($buf,0,$take) or die "Report write: $!\n"; }
            $nbytes += $take; $bytes_written += $take;
            if ($take < $n) { $reason='OUTPUT_LIMIT'; last; }
        }
        last if $reason;
        # Keep the leader unreaped until its output pipes close. This keeps its
        # PID from being reused while a descendant could still hold a pipe.
        unless ($sel->count) {
            my $w = waitpid($pid,WNOHANG);
            if ($w == $pid) { $rc=$?; last; }
            if ($w == -1) { $reason='WAIT_ERROR'; last; }
            sleep 0.05;
        }
    }
    if ($reason) { stop_child(); }
    else { $active_child=0; }
    for my $h ($sel->handles) { close $h; }
    close $fo; close $fe;
    my $state = $reason || (($rc||0)==0 ? 'OK' : 'ERROR');
    $status{$label}=$state;
    my $exit = defined $rc ? ($rc >> 8).'/signal='.($rc & 127) : '';
    emit('commands',utc(),$label,$state,$exit,sprintf('%.3f',time-$t0),join(' ',@argv));
    coverage($label,$state,"raw/$label.stdout; raw/$label.stderr") if $state ne 'OK';
    return "$base.stdout";
}
sub read_small {
    my ($path,$cap) = @_;
    open my $f,'<',$path or return '';
    my $buf=''; read($f,$buf,$cap); close $f;
    return $buf;
}
sub secure_open {
    my ($p) = @_;
    my @s=lstat($p);
    return (undef,undef) unless @s && S_ISREG($s[2]);
    my $flags = O_RDONLY;
    $flags |= eval { Fcntl::O_NOFOLLOW() } || 0;
    sysopen(my $f,$p,$flags) or return (undef,undef);
    my @a=stat($f);
    unless (@a && S_ISREG($a[2]) && $s[0]==$a[0] && $s[1]==$a[1]) { close $f; return (undef,undef); }
    return ($f,\@a);
}
sub hash_one {
    my ($p,$purpose) = @_;
    return if $hashed{$p}++;
    guard();
    unless ($has_sha) { coverage($p,'HASH_UNAVAILABLE','Digest::SHA missing'); return; }
    my ($f,$s)=secure_open($p);
    unless ($f) { coverage($p,'HASH_SKIPPED','missing, unreadable, symlink or non-regular'); return; }
    if ($s->[7]>$filehashcap || $hashbytes+$s->[7]>$hashcap) {
        close $f; coverage($p,'HASH_LIMIT','per-file or aggregate hashing limit'); return;
    }
    my $d=Digest::SHA->new(256);
    my ($nread,$err,$t0)=(0,'',time);
    while (1) {
        guard();
        if (time-$t0>30) { $err='HASH_TIMEOUT'; last; }
        my $buf=''; my $n=sysread($f,$buf,262144);
        if (!defined $n) { $err='HASH_READ_ERROR'; last; }
        last unless $n;
        $nread+=$n; $hashbytes+=$n;
        if ($nread>$filehashcap || $hashbytes>$hashcap) { $err='HASH_LIMIT'; last; }
        $d->add($buf);
    }
    my @after=stat($f); close $f;
    $err ||= 'CHANGED_DURING_HASH' if !@after || $s->[7]!=$after[7] || $s->[9]!=$after[9] || $s->[10]!=$after[10] || $nread!=$s->[7];
    if ($err) { coverage($p,$err,$purpose); return; }
    my $hex=$d->hexdigest;
    $hashes{$p}=$hex;
    emit('hashes',$hex,$p,$s->[7],$s->[9],$purpose);
}
sub classify_log {
    my ($line)=@_;
    my $n=lc($line);
    $n =~ s/%([0-9a-f]{2})/chr(hex($1))/ge; # one decoding pass, not exhaustive
    my $ppe = $n =~ /pitboss/ && $n =~ /(?:nsppe|ppe)/ && $n =~ /(?:unexpectedly died|missed too many heartbeats)/;
    if ($ppe) {
        return ('PRIORITY_REVIEW','PPE_TEXT_IN_AUTH_CONTEXT') if $n =~ /(?:aaad api|aaad resp|process_kernel_socket|login[=:]|username[=:]|user[=:])/;
        return ('REVIEW','PPE_TEXT_WITH_SHELL_SYNTAX') if $n =~ /[;`|<>]|\$\(/;
        return ('CONTEXT','PPE_CRASH_OR_HEARTBEAT');
    }
    return ('CONTEXT','KERNEL_OR_CRASH_EVENT') if $n =~ /(?:panic:|fatal trap|kernel trap|watchdog timeout|segmentation fault|page fault)/;
    return ('REVIEW','MODULE_OR_PRELOAD_LOG') if $n =~ /(?:\bkldload\b|\bkldunload\b|ld_preload|ld_libmap)/;
    return ('REVIEW','PRIVILEGED_CONFIG_LOG') if $n =~ /(?:add|set|rm|bind)\s+system\s+(?:user|cmdpolicy|group)\b/;
    return ('CONTEXT','SSH_AUTH_EVENT') if $n =~ /sshd.*(?:accepted|failed|invalid user|session opened)/;
    return ();
}
sub code_patterns {
    my ($s)=@_;
    my @r;
    push @r,'ENCODED_EVAL' if $s =~ /eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(/i;
    push @r,'REQUEST_AND_COMMAND_FUNCTION' if $s =~ /\$_(?:GET|POST|REQUEST|COOKIE)\b/ && $s =~ /\b(?:system|exec|passthru|shell_exec|popen)\s*\(/i;
    push @r,'JAVA_PROCESS_EXECUTION' if $s =~ /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|new\s+ProcessBuilder\s*\(/;
    push @r,'PRELOAD_DIRECTIVE' if $s =~ /\b(?:LD_PRELOAD|LD_LIBMAP|LD_LIBRARY_PATH)\s*=/;
    return @r;
}
sub inspect_text {
    my ($p,$persist)=@_;
    my ($f,$s)=secure_open($p);
    unless ($f) { coverage($p,'TEXT_SKIPPED','unreadable, symlink or non-regular'); return; }
    my $cap= $persist ? 262144 : 1048576;
    if ($s->[7]>$cap) { close $f; coverage($p,'TEXT_SIZE_SKIP',"size=$s->[7] cap=$cap"); return; }
    my $buf=''; my $n=read($f,$buf,$cap+1); close $f;
    unless (defined $n) { coverage($p,'TEXT_READ_ERROR',"$!"); return; }
    return if index($buf,"\0")>=0;
    if ($persist) {
        emit('persistence',"FILE $p",$buf);
    }
    my @r=code_patterns($buf);
    for my $rule (@r) { finding('REVIEW',$rule,$p,'Heuristic only; legitimate vendor/admin code may match. Review against same-build trusted reference.'); }
}
sub inventory_tree {
    my ($root,$kind)=@_;
    guard();
    my @rs=lstat($root);
    unless (@rs) { coverage($root,'ABSENT','inventory root'); return; }
    my @stack=([$root,0]); my $t0=time; my $num=0;
    my $limit=$deep ? 90:40;
    while (@stack) {
        guard();
        if ($entry_count >= $entrycap || time-$t0>$limit) {
            coverage($root,'INVENTORY_LIMIT',"entries=$num; remaining subtrees not inspected"); return;
        }
        my ($p,$depth)=@{pop @stack};
        next if $p eq $out || index($p,"$out/")==0;
        next if $seen{$p}++;
        my @s=lstat($p);
        unless (@s) { coverage($p,'STAT_FAILED',"$!"); next; }
        $entry_count++; $num++;
        my $type=S_ISDIR($s[2])?'dir':S_ISREG($s[2])?'file':S_ISLNK($s[2])?'symlink':'other';
        my $link=$type eq 'symlink' ? readlink($p):'';
        my $recent=($s[9]>=time-$days*86400 || $s[10]>=time-$days*86400) ? 1:0;
        emit('inventory',$p,$type,sprintf('%06o',$s[2]&07777),$s[4],$s[5],$s[7],$s[9],$s[10],$s[1],$s[0],$recent,$link);
        if ($type eq 'dir') {
            if ($s[0]!=$rs[0]) { coverage($p,'MOUNT_BOUNDARY','not descended'); next; }
            if ($depth>=10) { coverage($p,'DEPTH_LIMIT','not descended'); next; }
            opendir(my $d,$p) or do { coverage($p,'READDIR_FAILED',"$!"); next; };
            # Bound directory enumeration too; never build an unbounded file list.
            my $children=0;
            while (defined(my $n=readdir($d))) {
                next if $n eq '.' || $n eq '..';
                if (++$children>$entrycap) { coverage($p,'DIRECTORY_LIMIT','partial directory'); last; }
                push @stack,["$p/$n",$depth+1];
            }
            closedir $d; next;
        }
        next unless $type eq 'file';
        $inventory{$p}=1;
        if ($s[2]&06000) { finding('REVIEW','SUID_SGID_FILE',$p,'Permission inventory; expected vendor binaries also match.'); }
        if (($s[2]&0002) && $kind =~ /^(?:system|web|persistence)$/) {
            finding('REVIEW','WORLD_WRITABLE_SENSITIVE_PATH',$p,'Review owner, permissions and vendor baseline.');
        }
        # Record ALL dates; recent flag is context, never a malware verdict.
        if ($kind eq 'kernel' && ($p =~ /\.(?:ko|gz)$/ || $p =~ m{/(?:kernel|ns-[^/]+)$})) {
            $hash_queue{$p}='kernel_or_boot_module';
        }
        my $web = $p =~ m{^/(?:netscaler/(?:ns_gui|portal)|var/(?:vpn|netscaler/(?:gui|portal)))/};
        my $code = $p =~ /\.(?:php[0-9]?|phtml|pl|py|cgi|jsp|jspx|sh|js|tt|inc)$/i;
        if ($web && $code) { $hash_queue{$p}='web_code'; inspect_text($p,0); }
        if ($kind eq 'persistence') {
            # No private SSH keys or account password databases are copied.
            if ($p =~ m{/(?:cron\.d|cron/tabs|spool/cron|rc\.d)/} || $p =~ m{/(?:authorized_keys2?|rc\.netscaler|rc\.conf(?:\.local)?|rc\.local|loader\.conf(?:\.local)?|crontab|sshd_config|inetd\.conf|libmap\.conf|profile|\.profile|\.cshrc|\.login)$}) {
                $hash_queue{$p}='persistence'; inspect_text($p,1);
            }
        }
        if (($kind eq 'temporary') && ($s[2]&0111)) {
            finding('REVIEW','EXECUTABLE_IN_TEMP',$p,'May be administrative/vendor file; correlate with process paths and deployment time.');
            $hash_queue{$p}='temporary_executable';
        }
    }
    coverage($root,'INVENTORIED',"entries=$num; same filesystem, depth<=10");
}
sub collect_logs {
    my @roots=@_ ? @_ : ('/var/log','/var/nslog');
    my @logs;
    my @q=map {[$_,0]} @roots;
    my $count=0;
    while (@q) {
        guard(); my ($p,$depth)=@{pop @q}; my @s=lstat($p);
        unless (@s) { coverage($p,'LOG_PATH_ABSENT','not inspected'); next; }
        if (++$count>20000) { coverage('logs','DISCOVERY_LIMIT','partial log discovery'); last; }
        if (S_ISLNK($s[2])) { coverage($p,'LOG_SYMLINK_SKIPPED','target not followed'); next; }
        if (S_ISDIR($s[2]) && $depth>=3) { coverage($p,'LOG_DEPTH_LIMIT','not descended'); next; }
        if (S_ISDIR($s[2]) && $depth<3) {
            opendir(my $d,$p) or do { coverage($p,'LOG_DIR_UNREADABLE',"$!"); next; };
            while (defined(my $n=readdir($d))) {
                next if $n eq '.' || $n eq '..';
                if (@q>20000) { coverage($p,'LOG_DIRECTORY_LIMIT','partial directory enumeration'); last; }
                push @q,["$p/$n",$depth+1];
            }
            closedir $d;
        } elsif (S_ISREG($s[2])) {
            my ($name)=$p =~ m{([^/]+)$};
            if ($name =~ /^(?:ns\.log|messages|auth\.log|secure|cron|sshd|httpaccess|httperror|httpd[-_]|error_log|access_log|bash\.log|notice\.log|user\.log|daemon\.log|kern\.log)/i) {
                push @logs,[$p,$s[9],$s[7]];
            }
        }
    }
    @logs=sort {$b->[1]<=>$a->[1]} @logs;
    my $maxfiles=$deep ? 300:100;
    my $percap=($deep?32:8)*1024*1024;
    my $selected=0; my $totalmatches=0;
    for my $e (@logs) {
        guard(); my ($p,$mtime,$size)=@$e;
        if (++$selected>$maxfiles || $readbytes>=$readcap) { emit('logs', $p,$size,$mtime,'BUDGET_SKIP',0,0,''); next; }
        if ($p =~ /\.(?:bz2|xz|zip|Z)$/) { emit('logs',$p,$size,$mtime,'UNSUPPORTED_COMPRESSION',0,0,''); next; }
        my ($f,$s)=secure_open($p);
        unless ($f) { emit('logs',$p,$size,$mtime,'OPEN_FAILED',0,0,''); next; }
        my ($stream,$offset,$mode)=($f,0,'plain-tail');
        my $allow=$percap;
        $allow=$readcap-$readbytes if $allow>$readcap-$readbytes;
        if ($p =~ /\.gz$/) {
            unless ($has_gunzip) { close $f; emit('logs',$p,$size,$mtime,'GUNZIP_MODULE_MISSING',0,0,''); next; }
            $stream=IO::Uncompress::Gunzip->new($f,MultiStream=>1);
            unless ($stream) { close $f; emit('logs',$p,$size,$mtime,'GZIP_OPEN_FAILED',0,0,''); next; }
            $mode='gzip-prefix';
        } elsif ($size>$allow) {
            $offset=$size-$allow;
            unless (seek($f,$offset,0)) { close $f; emit('logs',$p,$size,$mtime,'SEEK_FAILED',0,0,''); next; }
        }
        my ($buf,$used,$lines,$matches,$longlines,$state)=('',0,0,0,0,'COMPLETE');
        my $alerts=0;
        my $dropfirst=$offset>0;
        my $discardlong=0;
        my $t0=time;
        my $consume=sub {
            my ($line)=@_; $lines++;
            if ($dropfirst) { $dropfirst=0; return; } # skip first partial tail line
            my @c=classify_log($line); return unless @c;
            $matches++;
            if ($totalmatches<5000) {
                emit('matches',$c[0],$c[1],$p,$mode,$offset,$lines,substr($line,0,8192));
                $totalmatches++;
            }
            if ($c[0] ne 'CONTEXT' && ++$alerts<=100) {
                finding($c[0],$c[1],"$p:scanned-line-$lines",'Review context; not proof of successful execution. See log_matches.tsv and original log.');
            }
        };
        while ($used<$allow) {
            guard();
            if (time-$t0>20) { $state='TIME_LIMIT'; last; }
            my $chunk=''; my $want=65536;
            $want=$allow-$used if $want>$allow-$used;
            my $n=$mode eq 'gzip-prefix' ? $stream->read($chunk,$want) : read($f,$chunk,$want);
            if (!defined($n) || $n<0) { $state='READ_ERROR'; last; }
            last unless $n;
            $used+=$n; $readbytes+=$n; $buf.=$chunk;
            while ((my $i=index($buf,"\n"))>=0) {
                my $line=substr($buf,0,$i+1,'');
                if ($discardlong) { $discardlong=0; next; }
                if (length($line)>32768) { $line=substr($line,0,32768); $longlines++; }
                $consume->($line);
            }
            if (length($buf)>32768) {
                $consume->(substr($buf,0,32768)) unless $discardlong;
                $longlines++ unless $discardlong;
                $buf=''; $discardlong=1;
            }
        }
        $consume->($buf) if length($buf) && !$discardlong;
        $state='BYTE_LIMIT_OR_EXACT_BOUNDARY' if $used>=$allow && $state eq 'COMPLETE';
        $state='TAIL_ONLY' if $offset>0 && $state eq 'COMPLETE';
        $stream->close() if $mode eq 'gzip-prefix'; close $f;
        emit('logs',$p,$size,$mtime,$state,$offset,$used,"$mode; matches=$matches; noncontext=$alerts; findings_emitted<=100; long_lines_truncated=$longlines");
    }
    coverage('log_scan','BOUNDED',"discovered=".scalar(@logs)."; scanned byte budget=$readcap; matches saved<=5000; text logs only");
}
sub process_views {
    my ($before,$binaries,$sockets,$after)=@_;
    unless (($status{ps_before}||'') eq 'OK' && ($status{ps_after}||'') eq 'OK') {
        coverage('pid_crosscheck','SKIPPED','needs both successful ps snapshots'); return;
    }
    my (%a,%b);
    for my $pair ([$before,\%a],[$after,\%b]) {
        for my $l (split /\n/,read_small($pair->[0],$cmdcap)) { $pair->[1]{$1}=1 if $l =~ /^\s*(\d+)\s/; }
    }
    for my $src (['procstat_b',$binaries,0],['sockstat_all',$sockets,2]) {
        next unless ($status{$src->[0]}||'') eq 'OK';
        for my $l (split /\n/,read_small($src->[1],$cmdcap)) {
            $l =~ s/^\s+//; my @v=split /\s+/,$l;
            my $pid=$v[$src->[2]]; next unless defined($pid) && $pid =~ /^\d+$/;
            next if $a{$pid} || $b{$pid};
            emit('crosscheck',$pid,$src->[0],'ABSENT_FROM_BOTH_PS_SNAPSHOTS',$l);
            finding('REVIEW','PID_VIEW_DIFFERENCE',"$src->[0]:pid=$pid",'Sampling race, short-lived collector process or format difference is possible. Not a hidden-process verdict.');
        }
    }
}
sub compare_baseline {
    return unless length $baseline;
    my ($f,$st)=secure_open($baseline);
    unless ($f) { coverage('baseline','OPEN_FAILED',$baseline); return; }
    if ($st->[7]>16*1024*1024) { close $f; coverage('baseline','SIZE_LIMIT',$baseline); return; }
    my %ref; my $bad=0;
    while (my $l=<$f>) {
        chomp $l; my @c=split /\t/,$l;
        next if $l =~ /^sha256\t/;
        if (@c<2 || $c[0]!~/^[a-fA-F0-9]{64}$/) { $bad++; next; }
        my $p=unesc($c[1]);
        if ($p!~m{^/} || $p =~ /[\x00-\x1f\x7f]/ || exists $ref{$p}) { $bad++; next; }
        $ref{$p}=lc $c[0];
    }
    close $f;
    if ($bad) { coverage('baseline','INVALID_ROWS',"$bad rows; no comparison performed"); return; }
    for my $p (sort keys %ref) {
        guard();
        my $v = !exists($hashes{$p}) ? 'NOT_COLLECTED' : $hashes{$p} eq $ref{$p} ? 'MATCH' : 'DIFFERENT';
        emit('baseline',$p,$v,$ref{$p},$hashes{$p}||'');
        finding('PRIORITY_REVIEW','TRUSTED_BASELINE_DIFF',$p,'Different file bytes; validate reference build/platform, vendor update and authorized changes. Not automatically malware.') if $v eq 'DIFFERENT';
    }
    coverage('baseline','COMPARED',scalar(keys %ref).' reference paths; NOT_COLLECTED does not mean deleted');
}
sub make_reports {
    my %headers=(
        findings=>'level code evidence interpretation',
        coverage=>'utc item state detail',
        commands=>'utc label state exit_and_signal elapsed_seconds argv_display_only',
        hashes=>'sha256 path size mtime_epoch purpose',
        inventory=>'path type mode uid gid size mtime_epoch ctime_epoch inode device recent link_target',
        persistence=>'source escaped_content',
        matches=>'level rule path scan_mode start_byte_offset scanned_line escaped_excerpt',
        logs=>'path disk_size mtime_epoch state start_byte_offset scanned_bytes detail',
        crosscheck=>'pid source state raw_line',
        baseline=>'path state reference_sha256 observed_sha256',
    );
    my %names=(findings=>'findings.tsv',coverage=>'coverage.tsv',commands=>'command_status.tsv',
        hashes=>'hashes.tsv',inventory=>'file_inventory.tsv',persistence=>'persistence.txt',
        matches=>'log_matches.tsv',logs=>'log_coverage.tsv',crosscheck=>'process_crosscheck.tsv',baseline=>'baseline_compare.tsv');
    for my $k (keys %names) {
        open my $h,'>',"$out/$names{$k}" or die "Cannot create report: $!\n";
        $fh{$k}=$h; emit($k,split / /,$headers{$k});
    }
}
sub collect {
    my @basic=(
        ['date','date','-u'], ['uname','uname','-a'], ['uptime','uptime'],
        ['mount','mount','-p'], ['df','df','-k'], ['swapinfo','swapinfo','-k'],
        ['dmesg','dmesg','-a'], ['kldstat','kldstat','-v'],
        ['kenv','kenv'], ['vmstat','vmstat','-s'], ['vmstat_interrupts','vmstat','-i'],
        ['vmstat_malloc','vmstat','-m'], ['vmstat_zones','vmstat','-z'],
        ['ifconfig','ifconfig','-a'], ['routes_bsd','netstat','-rn'],
        ['netstat','netstat','-an'], ['arp','arp','-an'], ['ndp','ndp','-an'],
        ['who','who'], ['last','last','-n','80'], ['root_crontab','crontab','-l','-u','root'],
        ['atq','atq'], ['ldconfig','ldconfig','-r'], ['ipcs','ipcs','-a'],
    );
    # Volatile process/network data first; each output is a separate snapshot.
    my $ps1=run_capture('ps_before',15,'ps','-axww','-o','pid,ppid,uid,gid,lstart,etime,state,%cpu,%mem,command');
    my $pb=run_capture('procstat_b',20,'procstat','-a','-b');
    my $so=run_capture('sockstat_all',20,'sockstat','-46');
    run_capture('sockstat_unix',15,'sockstat','-u');
    my $ps2=run_capture('ps_after',15,'ps','-axww','-o','pid,ppid,uid,gid,lstart,etime,state,%cpu,%mem,command');
    process_views($ps1,$pb,$so,$ps2);
    for my $c (@basic) { my ($label,@args)=@$c; run_capture($label,20,@args); }
    for my $oid (qw(kern.version kern.osrelease kern.osreldate kern.boottime kern.bootfile
        kern.module_path kern.securelevel kern.proc.all kern.smp.cpus hw.model hw.physmem
        security.bsd.see_other_uids security.bsd.see_other_gids security.bsd.unprivileged_proc_debug
        security.mac vm.stats.vm net.inet.ip.forwarding)) {
        next if $oid eq 'kern.proc.all'; # binary/internal tree; use ps/procstat
        (my $tag=$oid)=~s/\./_/g;
        run_capture("sysctl_$tag",15,'sysctl',$oid); # NEVER sysctl -w or assignments
    }
    for my $c (['ns_version','show ns version'],['ns_hardware','show ns hardware'],
        ['ha_node','show ha node'],['ha_syncfailures','show ha syncFailures'],
        ['ns_mode','show ns mode'],['ns_feature','show ns feature'],['ns_route','show route']) {
        run_capture($c->[0],20,'nscli','-c',$c->[1]);
    }
    # Running binary paths: no procstat environment collection.
    my @pids;
    if (($status{procstat_b}||'') eq 'OK') {
        for my $l (split /\n/,read_small($pb,$cmdcap)) {
            next unless $l =~ /^\s*(\d+)\s+\S+\s+\S+\s+(\/.*)\s*$/;
            my ($pid,$path)=($1,$2); $path =~ s/\s+$//;
            push @pids,$pid;
            $hash_queue{$path}='running_binary';
            if ($path =~ m{^/(?:tmp|var/tmp|var/run)/}) {
                finding('PRIORITY_REVIEW','RUNNING_FROM_WRITABLE_LOCATION',"pid=$pid $path",'Review process ancestry and authorized activity; not proof by itself.');
            }
        }
    }
    if ($deep) {
        run_capture('kernel_stacks_all',30,'procstat','-a','-k');
        run_capture('threads_all',20,'procstat','-a','-t');
        my %done; @pids=grep {!$done{$_}++ && $_!=$$} @pids;
        my $pmax=128; my $selected=0;
        for my $pid (@pids) {
            if (++$selected>$pmax) { coverage('deep_process','PID_LIMIT','only first 128 resolved binary PIDs'); last; }
            for my $a (['maps','-v'],['files','-f'],['cred','-s']) {
                my $f=run_capture("pid_${pid}_$a->[0]",8,'procstat',$a->[1],$pid);
                if ($a->[0] eq 'maps' && $f && ($status{"pid_${pid}_maps"}||'') eq 'OK') {
                    my $n=0;
                    for my $l (split /\n/,read_small($f,$cmdcap)) {
                        next unless $l =~ /^\s*\d+\s+\S+\s+\S+\s+rwx\s/;
                        last if ++$n>10;
                        finding('REVIEW','RWX_MAPPING',"pid=$pid",$l.' ; JIT/vendor mappings can be legitimate.');
                    }
                }
            }
        }
    } else { coverage('deep_process','NOT_REQUESTED','use --deep for maps/files/credentials/kernel stacks'); }
    # Hash the tools used to observe the machine, not just vendor programs.
    for my $name (qw(ps procstat sockstat netstat sysctl kldstat sh perl nscli sshd cron)) {
        my $p=resolve($name); $hash_queue{$p}='collector_or_system_tool' if $p;
    }
    $hash_queue{$^X}='perl_interpreter';
    if (defined($ENV{NS_TRIAGE_SOURCE})) {
        my $source=abs_path($ENV{NS_TRIAGE_SOURCE});
        $hash_queue{$source}='collector_source' if defined $source;
    }
    for my $p (qw(/netscaler/ns_monuploadd_err.pl /netscaler/nsppe /netscaler/pitboss /netscaler/nsaaad
        /sbin/init /boot/kernel/kernel /kernel)) { $hash_queue{$p}='critical_binary_or_script' if -e $p; }
    my $bootfile=read_small("$out/raw/sysctl_kern_bootfile.stdout",65536);
    if ($bootfile =~ /^kern\.bootfile:\s+(\/[^\r\n]+)$/m) { $hash_queue{$1}='running_kernel_backing_file'; }
    # kldstat names -> candidates only. Do not assert disk file == loaded bytes.
    my $mp=read_small("$out/raw/sysctl_kern_module_path.stdout",65536);
    $mp =~ s/^kern\.module_path:\s*//; $mp =~ s/[\r\n]+$//;
    my @modulepaths=grep {m{^/} && !/[\x00-\x1f]/} split /;/,$mp;
    push @modulepaths, '/boot/kernel','/boot/modules','/netscaler';
    for my $l (split /\n/,read_small("$out/raw/kldstat.stdout",$cmdcap)) {
        next unless $l =~ /^\s*\d+\s+\d+\s+(?:0x)?[0-9a-f]+\s+(?:0x)?[0-9a-f]+\s+(\S+)/i;
        my $name=$1; next if $name =~ m{(?:^|/)\.\.(?:/|$)};
        if ($name =~ m{^/}) { $hash_queue{$name}='loaded_module_name_candidate'; next; }
        for my $d (@modulepaths) { $hash_queue{"$d/$name"}='loaded_module_name_candidate' if -f "$d/$name"; }
    }
    # Critical hashes before potentially lengthy traversal.
    for my $p (sort keys %hash_queue) { hash_one($p,$hash_queue{$p}); }
    inspect_text('/netscaler/ns_monuploadd_err.pl',1) if -f '/netscaler/ns_monuploadd_err.pl';
    my @roots=(['/boot','kernel'],['/nsconfig','persistence'],['/etc/cron.d','persistence'],
        ['/var/cron/tabs','persistence'],['/var/spool/cron','persistence'],
        ['/etc/rc.d','persistence'],['/usr/local/etc/rc.d','persistence'],
        ['/root/.ssh','persistence'],['/netscaler/ns_gui','web'],['/netscaler/portal','web'],
        ['/var/vpn','web'],['/var/netscaler/gui','web'],['/var/netscaler/portal','web'],
        ['/tmp','temporary'],['/var/tmp','temporary'],['/var/core','core'],['/var/crash','core']);
    for my $r (@roots) { inventory_tree(@$r); }
    if ($deep) { inventory_tree('/netscaler','system'); inventory_tree('/bin','system'); inventory_tree('/sbin','system'); }
    for my $p (qw(/etc/crontab /etc/rc.conf /etc/rc.conf.local /etc/rc.local /etc/inetd.conf
        /etc/libmap.conf /etc/profile /etc/ssh/sshd_config /root/.profile /root/.cshrc /root/.login
        /boot/loader.conf /boot/loader.conf.local)) {
        next unless -e $p; $hash_queue{$p}='persistence'; inspect_text($p,1);
    }
    # Account metadata without password field or GECOS.
    my ($pf,$pst)=secure_open('/etc/passwd');
    if ($pf) {
        my $n=0;
        while (my $l=<$pf>) {
            last if ++$n>10000; my @v=split /:/,$l; next unless @v>=7;
            chomp $v[6]; emit('persistence','ACCOUNT',join(':',@v[0,2,3,5,6]));
            finding('REVIEW','ADDITIONAL_UID_ZERO',$v[0],'Validate against appliance account baseline.') if $v[2] eq '0' && $v[0] ne 'root';
        }
        close $pf;
    }
    for my $p (sort keys %hash_queue) { hash_one($p,$hash_queue{$p}); }
    collect_logs();
    compare_baseline();
}
sub finish {
    my ($result)=@_;
    for my $h (values %fh) { close $h; }
    open my $f,'>',"$out/SUMMARY.txt" or die "Cannot write summary: $!\n";
    print {$f} "NetScaler live triage v$VERSION\nStarted UTC: ".utc($started)."\nFinished UTC: ".utc()."\n";
    print {$f} "Run state: $result\nMode: ".($deep?'deep':'standard')."\n";
    print {$f} "PRIORITY_REVIEW: ".($findcount{PRIORITY_REVIEW}||0)."\nREVIEW: ".($findcount{REVIEW}||0)."\n";
    print {$f} "File entries: $entry_count\nLog bytes read: $readbytes\nBytes hashed: $hashbytes\n";
    print {$f} "Baseline: ".(length($baseline)?esc($baseline):'NONE - integrity verdict unavailable')."\n\n";
    print {$f} <<'SUMMARY';
NO CLEAN/COMPROMISED VERDICT IS GENERATED.
Start with findings.tsv, command_status.tsv, coverage.tsv and log_coverage.tsv.
An OK command means only that the utility returned zero. Some nscli errors
can be printed despite exit zero; inspect its stdout/stderr as well.
Missing tools, permissions, unsupported options, limits and snapshot races
reduce coverage. No matching log record does NOT rule out exploitation.
Logs may have rotated, been deleted, been truncated, or not recorded an event.
Plain logs are scanned from their tail; gzip logs from their decoded beginning.
Binary newnslog, core dumps and private keys are not content-scanned.
Log byte/line limits and file traversal/hash limits are explicit coverage gaps.
Log dates are not parsed; --days only marks filesystem mtime/ctime recency.

Kernel visibility comes from the running kernel and local tools. A rootkit
could hide or falsify these views. This does not inspect syscall hooks or RAM.
On-disk module hashes do not attest loaded module bytes or the live kernel.
Process maps and stacks are snapshots, not memory forensics. An absent stack
may reflect missing kernel options; RWX pages may be legitimate vendor/JIT code.
sockstat/netstat show the FreeBSD view, not all NetScaler PPE dataplane flows.
Same-build HA peers may both be compromised and are not trusted baselines.
Firmware updates and admin customizations can explain differing hashes.

Preserve this complete directory securely and hash it independently off-box.
evidence_sha256.tsv detects later changes only if its reference is protected;
hashing on a suspected machine cannot establish evidence authenticity.
Logs/argv/cron may contain credentials, session tokens or internal addresses.
No automatic redaction, transfer, archive, exploit, remediation or upload occurs.
Reads can change atime/cache; command execution can create audit records.
Bounded collection still consumes CPU and I/O. Keep external monitoring active.

High-priority suspicious findings should be correlated with off-box syslog,
firewall flows and an independent same-build reference. Preserve volatile
evidence before deciding on reboot or vendor-assisted forensic acquisition.
This custom collector is not a Citrix-supported compromise certification tool.

Sources (checked 2026-09-29):
https://man.freebsd.org/cgi/man.cgi?query=kldstat&sektion=8
https://man.freebsd.org/cgi/man.cgi?query=procstat&sektion=1
https://man.freebsd.org/cgi/man.cgi?query=sockstat&sektion=1
https://docs.netscaler.com/en-us/netscaler-application-delivery-management-software/current-release/instance-advisory/ioc.html
https://labs.watchtowr.com/oh-look-the-foot-gun-went-off-again-citrix-netscaler-preauth-command-injection-cve-2026-88771/
The CVE-related log rules are contextual hunt heuristics based on the supplied
research, not official signatures or an exhaustive list of exploit variants.
No patch status is inferred from a filename, regex or an assumed version.
SUMMARY
    close $f;
    if ($has_sha) {
        open my $m,'>',"$out/evidence_sha256.tsv" or die "$!\n";
        print {$m} "sha256\trelative_path\n";
        my @q=($out);
        while (@q) {
            my $p=pop @q;
            if (-d $p && !-l $p) {
                opendir(my $d,$p) or next;
                push @q,map {"$p/$_"} grep {$_ ne '.' && $_ ne '..'} readdir($d); closedir $d;
            } elsif (-f $p && !-l $p && $p ne "$out/evidence_sha256.tsv") {
                open my $r,'<',$p or next; binmode $r;
                my $h=Digest::SHA->new(256); $h->addfile($r); close $r;
                my $rel=substr($p,length($out)+1);
                print {$m} $h->hexdigest."\t".esc($rel)."\n";
            }
        }
        close $m;
    }
    print "\nCollection state: $result\nReport directory: $out\nRead SUMMARY.txt and coverage files first. No clean verdict.\n";
}
sub main {
    die "Root required for this live collection.\n" unless $> == 0;
    my @os=POSIX::uname();
    die "This collector targets FreeBSD NetScaler, not $os[0]. No collection performed.\n" unless $os[0] eq 'FreeBSD';
    die "NetScaler nscli not found. No collection performed.\n" unless resolve('nscli');
    die "Output parent must be an existing absolute directory.\n" unless $outparent =~ m{^/} && -d $outparent && !-l $outparent;
    $outparent=abs_path($outparent) or die "Cannot resolve output directory\n";
    # Reject shared/writable baseline symlinks. Baseline contents are NEVER executed.
    die "Baseline must be a readable regular non-symlink file.\n" if length($baseline) && (!-f $baseline || -l $baseline || !-r $baseline);
    $out=tempdir('ns_triage_'.POSIX::strftime('%Y%m%dT%H%M%SZ',gmtime()).'_XXXXXX',DIR=>$outparent,CLEANUP=>0);
    mkdir "$out/raw",0700 or die "$!\n";
    $started=time; $deadline=$started+$maxseconds;
    make_reports();
    $SIG{INT}=$SIG{TERM}=sub { die "INTERRUPTED\n"; };
    $SIG{ALRM}=sub { die "TIME_BUDGET\n"; };
    print "NetScaler triage v$VERSION. Output: $out\n";
    print "Collection budget: $maxseconds seconds. Queries only; reports contain sensitive data.\n";
    # Lower only this collector's scheduling priority; children inherit it.
    coverage('collector_priority',setpriority(0,0,10)?'NICE_10':'UNCHANGED',"$!");
    my $state='FINISHED_WITH_BOUNDED_COVERAGE';
    eval {
        alarm($maxseconds);
        my $df=run_capture('preflight_df',10,'df','-k',$out);
        my $raw=read_small($df,65536); my @lines=grep {/\S/} split /\n/,$raw;
        my @v=split /\s+/,$lines[-1]||'';
        die "Could not verify free disk space; inspect raw/preflight_df.*\n" unless ($status{preflight_df}||'') eq 'OK' && @v>=6 && $v[3]=~/^\d+$/;
        my $required=$maxout/1024+262144;
        die "Insufficient free space; need at least $required KiB for report budget plus reserve.\n" if $v[3]<$required;
        coverage('preflight_space','OK',"available_kib=$v[3]; required_kib=$required");
        coverage('Digest::SHA',$has_sha?'AVAILABLE':'MISSING','hashes unavailable if missing');
        coverage('IO::Uncompress::Gunzip',$has_gunzip?'AVAILABLE':'MISSING','compressed log scanning unavailable if missing');
        collect();
        1;
    } or do {
        my $error=$@ || 'unknown error'; stop_child();
        $state='INCOMPLETE: '.esc($error);
        eval { coverage('collection','INCOMPLETE',$error); };
    };
    alarm(0);
    $SIG{INT}=$SIG{TERM}=$SIG{ALRM}='DEFAULT';
    finish($state);
    exit($state =~ /^INCOMPLETE/ ? 2:0);
}
sub self_test {
    my $tests=0;
    my $assert=sub { my ($b,$n)=@_; die "FAIL $n\n" unless $b; $tests++; print "ok $tests - $n\n"; };
    my @v=classify_log('pitboss: NSPPE-00 (12345) unexpectedly died');
    $assert->($v[0] eq 'CONTEXT','ordinary crash is context, not exploit verdict');
    @v=classify_log('AAAD RESP user=pitboss PPE unexpectedly died NSPPE-00');
    $assert->($v[0] eq 'PRIORITY_REVIEW','auth-context crash marker');
    @v=classify_log('pitboss PPE unexpectedly died NSPPE-00%3bmarker');
    $assert->($v[1] eq 'PPE_TEXT_WITH_SHELL_SYNTAX','encoded metacharacter');
    @v=classify_log('sshd: Accepted publickey for nsroot');
    $assert->($v[0] eq 'CONTEXT','SSH auth is context');
    @v=classify_log('ordinary service event'); $assert->(!@v,'unrelated log');
    @v=code_patterns('<?php echo "hello"; ?>'); $assert->(!@v,'ordinary code');
    @v=code_patterns('eval(base64_decode("fixture"));'); $assert->(@v==1,'encoded eval heuristic');
    my $s="/tmp/a\\x20\tb\nc"; $assert->(unesc(esc($s)) eq $s,'TSV escaping round trip');
    $out=tempdir('netscaler_triage_test_XXXXXX',TMPDIR=>1,CLEANUP=>1);
    mkdir "$out/raw",0700 or die "$!\n";
    $started=time; $deadline=$started+30; make_reports();
    my $f=run_capture('fixture_ok',2,$^X,'-e','print "hello"; warn "stderr";');
    $assert->($status{fixture_ok} eq 'OK' && read_small($f,100) eq 'hello','runner captures stdout separately');
    run_capture('fixture_error',2,$^X,'-e','exit 7');
    $assert->($status{fixture_error} eq 'ERROR','nonzero exit reported');
    run_capture('fixture_timeout',0.2,$^X,'-e','sleep 10');
    $assert->($status{fixture_timeout} eq 'TIMEOUT','runner bounds time');
    run_capture('fixture_descendant',0.2,$^X,'-e','my $p=fork(); if (!$p) {sleep 10} else {exit 0}');
    $assert->($status{fixture_descendant} eq 'TIMEOUT','descendant-held pipe is bounded after leader exits');
    my $old=$cmdcap; $cmdcap=1024;
    run_capture('fixture_output',2,$^X,'-e','print "x" x 100000'); $cmdcap=$old;
    $assert->($status{fixture_output} eq 'OUTPUT_LIMIT','runner bounds output');
    $assert->((-s "$out/raw/fixture_output.stdout")<=1024,'output size bounded');
    my $q="$out/hashfixture";
    open my $w,'>',$q or die $!; print {$w} 'abc'; close $w;
    hash_one($q,'test');
    $assert->(!$has_sha || $hashes{$q} eq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','SHA256 fixture');
    symlink($q,"$out/symlink") or die $!;
    my ($r)=secure_open("$out/symlink"); $assert->(!$r,'symlink content is not opened');
    my $logdir=tempdir('netscaler_log_fixture_XXXXXX',TMPDIR=>1,CLEANUP=>1);
    open $w,'>',"$logdir/ns.log" or die $!;
    my $plain_fixture="pitboss: NSPPE-00 (12345) unexpectedly died\nAAAD RESP login=pitboss PPE unexpectedly died NSPPE-00\n";
    print {$w} $plain_fixture;
    close $w;
    my $gzip_fixture="pitboss: NSPPE-01 (12346) missed too many heartbeats\n";
    my $gztest=$has_gunzip && eval { require IO::Compress::Gzip; 1 };
    if ($gztest) {
        IO::Compress::Gzip::gzip(\$gzip_fixture => "$logdir/ns.log.1.gz") or die "gzip test fixture failed\n";
    }
    collect_logs($logdir);
    $assert->(($findcount{PRIORITY_REVIEW}||0)==1,'log fixture produces exactly one priority review');
    $assert->($readbytes==length($plain_fixture)+($gztest?length($gzip_fixture):0),'plain and available gzip content actually scanned');
    my $bf="$out/baseline_fixture.tsv";
    open $w,'>',$bf or die $!;
    print {$w} "sha256\tpath\n",('0' x 64)."\t".esc($q)."\n",('1' x 64)."\t/not-collected\n";
    close $w; $baseline=$bf;
    compare_baseline();
    $assert->(!$has_sha || ($findcount{PRIORITY_REVIEW}||0)==2,'baseline difference is review, missing collection is not malware');
    open $w,'>',"$logdir/authorized_keys" or die $!; print {$w} 'public fixture'; close $w;
    inventory_tree($logdir,'persistence');
    $assert->(exists $inventory{"$logdir/authorized_keys"},'bounded file inventory');
    for my $h (values %fh) { close $h; }
    print "PASS: $tests synthetic tests. No NetScaler command was run.\n";
}
if ($selftest) { self_test(); exit 0; }
main();
NS_TRIAGE_PERL
    fi
done
echo 'A compatible Perl interpreter is required; no collection performed.' >&2
exit 1
