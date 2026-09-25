# OpenSSH canonical event parser. Input is never evaluated as shell code.
BEGIN {
 out=ENVIRON["LAM_RUN"]
 events=out "/events.tsv"; alerts=out "/alerts.tsv"
 print "observed_epoch\tevent\tsource\tuser\tmethod" > events
 print "observed_epoch\talert\tsource\tcount\tscope" > alerts
 fflush(events); fflush(alerts)
}
function alert(kind, ip, count, now, scope) {
 scope=live ? "observation_window" : "whole_file"
 printf "%d\t%s\t%s\t%d\t%s\n",now,kind,ip,count,scope >> alerts
 printf "[ALERT] %s source=%s count=%d scope=%s\n",kind,ip,count,scope
 fflush(alerts); fflush()
}
function prune(ip, now) {
 if (!live) return
 while (head[ip] < end[ip] && now-times[ip,head[ip]] > window) {
  delete times[ip,head[ip]]; head[ip]++
 }
 if (end[ip]-head[ip] < limit) raised[ip]=0
}
{
 # Only canonical sshd/sshd-session prefixes, not arbitrary user log messages.
 if (!match($0, /sshd(-session)?\[[0-9]+\]: /)) next
 msg=substr($0,RSTART+RLENGTH)
 n=split(msg,a,/ +/)
 if (a[1]!="Failed" && a[1]!="Accepted") next
 if (a[2]!="password" && a[2]!="publickey" && a[2]!="keyboard-interactive/pam") next
 if (a[3]!="for") next
 pos=4
 if (a[pos]=="invalid" && a[pos+1]=="user") pos+=2
 user=a[pos]; ip=a[pos+2]
 if (a[pos+1]!="from" || a[pos+3]!="port" || a[pos+4]!~/^[0-9]+$/) next
 # Bound/sanitize untrusted tokens, including terminal-control characters.
 if (length(ip)>64 || ip!~/^[0-9a-fA-F:.]+$/) next
 if (length(user)>128 || user!~/^[a-zA-Z0-9_.@+-]+$/) user="[unparsed]"
 if (!(ip in head)) { head[ip]=0; end[ip]=0 }
 now=systime(); prune(ip,now)
 printf "%d\t%s\t%s\t%s\t%s\n",now,a[1],ip,user,a[2] >> events
 fflush(events)
 if (a[1]=="Failed") {
  total[ip]++; failures++
  if (live) {
   times[ip,end[ip]++]=now
   # Only the newest threshold events are needed to detect crossing.
   while (end[ip]-head[ip]>limit) {delete times[ip,head[ip]]; head[ip]++}
   count=end[ip]-head[ip]
  } else count=total[ip]
  if (count>=limit && !raised[ip]) {alert("REPEATED_FAILURES",ip,count,now); raised[ip]=1}
 } else {
  successes++
  count=live ? end[ip]-head[ip] : total[ip]+0
  if (count>=limit) alert("SUCCESS_AFTER_FAILURES_REVIEW",ip,count,now)
 }
}
END {
 summary=out "/summary.tsv"
 print "source\tfailed_events" > summary
 for(ip in total) printf "%s\t%d\n",ip,total[ip] >> summary
 close(summary)
 printf "Parsed failed events: %d | accepted events: %d\n",failures,successes
}
