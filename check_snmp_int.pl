#!/usr/bin/perl -w
############################## check_snmp_int_udt ##############
# Based on check_snmp_int by Patrick Proy (manubulon-snmp)
# Modified by UDT - added:
#   -F  --port-filter  : comma-separated list of port numbers to monitor
#   --perfonly         : always exit OK (exit 0), only emit perfdata
#
my $VERSION = "2.1.0-udt1";

use strict;
use Net::SNMP;
use Getopt::Long;

############### BASE DIRECTORY FOR TEMP FILE ########
my $o_base_dir    = "/tmp/tmp_Icinga_int.";
my $file_history  = 200;

my %ERRORS = ('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3,'DEPENDENT'=>4);

my $snmp_splice_size = 50;

# SNMP OIDs
my $inter_table       = '.1.3.6.1.2.1.2.2.1';
my $index_table       = '1.3.6.1.2.1.2.2.1.1';
my $descr_table       = '1.3.6.1.2.1.2.2.1.2';
my $name_table        = '1.3.6.1.2.1.31.1.1.1.1';
my $alias_table       = '.1.3.6.1.2.1.31.1.1.1.18';
my $oper_table        = '1.3.6.1.2.1.2.2.1.8.';
my $admin_table       = '1.3.6.1.2.1.2.2.1.7';
my $speed_table       = '1.3.6.1.2.1.2.2.1.5.';
my $speed_table_64    = '1.3.6.1.2.1.31.1.1.1.15.';
my $in_octet_table    = '1.3.6.1.2.1.2.2.1.10.';
my $in_octet_table_64 = '1.3.6.1.2.1.31.1.1.1.6.';
my $in_error_table    = '1.3.6.1.2.1.2.2.1.14.';
my $in_discard_table  = '1.3.6.1.2.1.2.2.1.13.';
my $out_octet_table    = '1.3.6.1.2.1.2.2.1.16.';
my $out_octet_table_64 = '1.3.6.1.2.1.31.1.1.1.10.';
my $out_error_table    = '1.3.6.1.2.1.2.2.1.20.';
my $out_discard_table  = '1.3.6.1.2.1.2.2.1.19.';

my %status = (
  1=>'UP', 2=>'DOWN', 3=>'TESTING', 4=>'UNKNOWN',
  5=>'DORMANT', 6=>'NotPresent', 7=>'lowerLayerDown'
);

# Standard options
my $o_host       = undef;
my $o_port       = 161;
my $o_domain     = 'udp/ipv4';
my $o_descr      = undef;
my $o_help       = undef;
my $o_admin      = undef;
my $o_inverse    = undef;
my $o_dormant    = undef;
my $o_down       = undef;
my $o_ignore_admindown  = undef;
my $o_ignore_emptyalias = undef;
my $o_verb       = undef;
my $o_version    = undef;
my $o_noreg      = undef;
my $o_short      = undef;
my $o_label      = undef;
my $o_weather    = undef;

# Performance data options
my $o_perf    = undef;
my $o_perfe   = undef;
my $o_perfs   = undef;
my $o_perfp   = undef;
my $o_perfr   = undef;

# Speed/error checks
my $o_checkperf     = undef;
my $o_delta         = 300;
my $o_ext_checkperf = undef;
my $o_warn_opt      = undef;
my $o_crit_opt      = undef;
my $o_kbits         = undef;
my @o_warn          = undef;
my @o_crit          = undef;
my $o_highperf      = undef;
my $o_meg           = undef;
my $o_gig           = undef;
my $o_prct          = undef;
my $o_use_ifname    = undef;
my $o_use_ifalias   = undef;
my $o_timeout       = undef;
my $o_octetlength   = undef;

# Login options
my $o_community  = undef;
my $o_version2   = undef;
my $o_login      = undef;
my $o_passwd     = undef;
my $v3protocols  = undef;
my $o_authproto  = 'md5';
my $o_privproto  = 'des';
my $o_privpass   = undef;

# ── UDT additions ────────────────────────────────────────────
my $o_port_filter = undef;   # -F  comma-separated port numbers
my $o_perfonly    = undef;   # --perfonly  always exit 0
# ─────────────────────────────────────────────────────────────

my @countername = ("in=","out=","errors-in=","errors-out=","discard-in=","discard-out=");
my $checkperf_out_desc;

# ── Subroutines ───────────────────────────────────────────────
sub read_file {
  my ($traffic_file,$items_number) = @_;
  my ($ligne,$n_rows) = (undef,0);
  my (@last_values,@file_values,$i);
  open(FILE,"<".$traffic_file) || return (1,0,0);
  while ($ligne=<FILE>) {
    chomp($ligne);
    @file_values=split(":",$ligne);
    if ($#file_values >= ($items_number-1)) {
      for ($i=0;$i<$items_number;$i++) { $last_values[$n_rows][$i]=$file_values[$i]; }
      $n_rows++;
    }
  }
  close FILE;
  if ($n_rows != 0) { return (0,$n_rows,@last_values); }
  else              { return (1,0,0); }
}

sub write_file {
  my ($file_out,$rows,$item,@file_values) = @_;
  my $start_line = ($rows > $file_history) ? $rows-$file_history : 0;
  if (open(FILE2,">".$file_out)) {
    for (my $i=$start_line;$i<$rows;$i++) {
      for (my $j=0;$j<$item;$j++) {
        print FILE2 $file_values[$i][$j];
        if ($j != ($item-1)) { print FILE2 ":"; }
      }
      print FILE2 "\n";
    }
    close FILE2;
    return 0;
  } else { return 1; }
}

sub p_version { print "check_snmp_int_udt version : $VERSION\n"; }

sub print_usage {
  print "Usage: $0 [-v] -H <host> -C <snmp_community> [-2] | (-l login -x passwd [-X pass -L <authp>,<privp>]) [-p <port>] { -n <name> | -F <port_list> } [-r] [-f[eSyY]] [-k[qBMGu] -g -w<warn> -c<crit> -d<delta>] [--perfonly] [-t <timeout>] [-V]\n";
}

sub isnnum {
  my $num = shift;
  if ($num =~ /^(\d+\.?\d*)|(^\.\d+)$/) { return 0; }
  return 1;
}

sub help {
  print "\nSNMP Network Interface Monitor (UDT fork), Version ",$VERSION,"\n";
  print "Based on check_snmp_int by Patrick Proy - GPL license\n\n";
  print_usage();
  print <<EOT;

-v, --verbose
    print extra debugging information
-h, --help
    print this help message
-H, --hostname=HOST
    name or IP address of host to check
-C, --community=COMMUNITY NAME
    community name for the host SNMP agent (implies v1 protocol)
-l, --login=LOGIN ; -x, --passwd=PASSWD
    Login and auth password for snmpv3 authentication
-2, --v2c
    use snmp v2c
-X, --privpass=PASSWD
    Priv password for snmpv3 (AuthPriv protocol)
-L, --protocols=<authproto>,<privproto>
    <authproto> : md5|sha  (default md5)
    <privproto> : des|aes  (default des)
-P, --port=PORT
    SNMP port (Default 161)
-n, --name=NAME
    Name in description OID (regexp). Mutually exclusive with -F.
-F, --port-filter=LIST
    Comma-separated list of port numbers to monitor.
    Example: -F "1,2,5,6,40,41,42,43,44,52"
    Internally builds a regexp matching those ports. Mutually exclusive with -n.
-r, --noregexp
    Do not use regexp to match NAME in description OID
-N, --use-ifname
    Use IF-MIB::ifName instead of IF-MIB::ifDescr
-A, --use-ifalias
    Use IF-MIB::ifAlias instead of IF-MIB::ifDescr
-i, --inverse
    Make critical when up
-a, --admin
    Use administrative status instead of operational
-D, --dormant
    Dormant state is an OK state
--down
    Down state is an OK state
--ign-admindown
    Ignore interfaces in Admin down state
--ign-emptyalias
    Ignore interfaces with empty alias
-o, --octetlength=INTEGER
    max-size of the SNMP message
-f, --perfdata
    Performance data output
-e, --error
    Add error & discard to Perfdata output
-S, --intspeed
    Include speed in performance output
-y, --perfprct
    output performance data in % of max speed
-Y, --perfspeed
    output performance data in bits/s or Bytes/s
-k, --perfcheck ; -q, --extperfcheck
    -k check the input/output bandwidth
    -q also check error and discard
-g, --64bits
    Use 64 bits counters (requires snmp v2c or v3)
-d, --delta=seconds
    average over <delta> seconds (default 300)
-B, --kbits
    warning/critical levels in Kbits/s
-G, --giga ; -M, --mega ; -u, --prct
    -G : levels in Gbps (with -B) or GBps
    -M : levels in Mbps (with -B) or MBps
    -u : levels in % of interface speed
-w, --warning=input,output[,error in,error out,discard in,discard out]
    warning level for input/output bandwidth
-c, --critical=input,output[,error in,error out,discard in,discard out]
    critical level for input/output bandwidth
--perfonly
    Always exit with status OK (exit 0) regardless of interface state.
    Useful when you only want perfdata for graphing, without alerts.
    Implies -f (perfdata enabled).
-s, --short=int
    Output only first <n> chars of interface name
-t, --timeout=INTEGER
    timeout for SNMP in seconds (Default: 5)
-V, --version
    prints version number

Examples:
  Monitor specific ports by number (no alerts, perfdata only):
    $0 -H 192.168.1.1 -l monuser -x authpass -X privpass -L SHA,AES \\
       -F "1,2,5,6,40,41,42,43,44,52" -g -Y -d 300 --perfonly

  Monitor one interface with bandwidth alerting:
    $0 -H 192.168.1.1 -l monuser -x authpass -X privpass -L SHA,AES \\
       -n "Slot: 0 Port: 52 10G - Level" -g -f -Y -k -w 8000000,8000000 -c 9000000,9000000 -d 300
EOT
}

sub verb { my $t=shift; print $t,"\n" if defined($o_verb); }

sub check_options {
  Getopt::Long::Configure("bundling");
  GetOptions(
    'v'             => \$o_verb,       'verbose'        => \$o_verb,
    'h'             => \$o_help,       'help'           => \$o_help,
    'H:s'           => \$o_host,       'hostname:s'     => \$o_host,
    'p:i'           => \$o_port,       'port:i'         => \$o_port,
    'protocol:s'    => \$o_domain,
    'n:s'           => \$o_descr,      'name:s'         => \$o_descr,
    'F:s'           => \$o_port_filter,'port-filter:s'  => \$o_port_filter,
    'N'             => \$o_use_ifname, 'use-ifname'     => \$o_use_ifname,
    'A'             => \$o_use_ifalias,'use-ifalias'    => \$o_use_ifalias,
    'C:s'           => \$o_community,  'community:s'    => \$o_community,
    '2'             => \$o_version2,   'v2c'            => \$o_version2,
    'l:s'           => \$o_login,      'login:s'        => \$o_login,
    'x:s'           => \$o_passwd,     'passwd:s'       => \$o_passwd,
    'X:s'           => \$o_privpass,   'privpass:s'     => \$o_privpass,
    'L:s'           => \$v3protocols,  'protocols:s'    => \$v3protocols,
    't:i'           => \$o_timeout,    'timeout:i'      => \$o_timeout,
    'i'             => \$o_inverse,    'inverse'        => \$o_inverse,
    'a'             => \$o_admin,      'admin'          => \$o_admin,
    'r'             => \$o_noreg,      'noregexp'       => \$o_noreg,
    'V'             => \$o_version,    'version'        => \$o_version,
    'f'             => \$o_perf,       'perfparse'      => \$o_perf,   'perfdata' => \$o_perf,
    'e'             => \$o_perfe,      'error'          => \$o_perfe,
    'k'             => \$o_checkperf,  'perfcheck'      => \$o_checkperf,
    'q'             => \$o_ext_checkperf,'extperfcheck' => \$o_ext_checkperf,
    'w:s'           => \$o_warn_opt,   'warning:s'      => \$o_warn_opt,
    'c:s'           => \$o_crit_opt,   'critical:s'     => \$o_crit_opt,
    'B'             => \$o_kbits,      'kbits'          => \$o_kbits,
    's:i'           => \$o_short,      'short:i'        => \$o_short,
    'g'             => \$o_highperf,   '64bits'         => \$o_highperf,
    'S'             => \$o_perfs,      'intspeed'       => \$o_perfs,
    'y'             => \$o_perfp,      'perfprct'       => \$o_perfp,
    'Y'             => \$o_perfr,      'perfspeed'      => \$o_perfr,
    'M'             => \$o_meg,        'mega'           => \$o_meg,
    'G'             => \$o_gig,        'giga'           => \$o_gig,
    'u'             => \$o_prct,       'prct'           => \$o_prct,
    'o:i'           => \$o_octetlength,'octetlength:i'  => \$o_octetlength,
    'label'         => \$o_label,
    'd:i'           => \$o_delta,      'delta:i'        => \$o_delta,
    'D'             => \$o_dormant,    'dormant'        => \$o_dormant,
    'down'          => \$o_down,
    'W'             => \$o_weather,    'weather'        => \$o_weather,
    'ign-admindown' => \$o_ignore_admindown,
    'ign-emptyalias'=> \$o_ignore_emptyalias,
    'perfonly'      => \$o_perfonly,
  );

  if (defined($o_help))    { help(); exit $ERRORS{"UNKNOWN"}; }
  if (defined($o_version)) { p_version(); exit $ERRORS{"UNKNOWN"}; }

  # ── UDT: build regexp from port filter ───────────────────
  if (defined($o_port_filter) && defined($o_descr)) {
    print "ERROR: -F (--port-filter) and -n (--name) are mutually exclusive.\n";
    print_usage();
    exit $ERRORS{"UNKNOWN"};
  }
  if (defined($o_port_filter)) {
    my @ports = split(/,\s*/, $o_port_filter);
    if (@ports == 0) {
      print "ERROR: -F requires at least one port number.\n";
      exit $ERRORS{"UNKNOWN"};
    }
    # Build regexp: matches "Port: X " where X is one of the listed numbers
    $o_descr = "Port: (" . join("|", @ports) . ") ";
    verb("Port filter built regexp: $o_descr");
  }

  # --perfonly implies -f (perfdata)
  if (defined($o_perfonly)) {
    $o_perf = 1;
  }
  # ─────────────────────────────────────────────────────────

  if (!defined($o_descr) || !defined($o_host)) {
    print "ERROR: Host (-H) and interface filter (-n or -F) are required.\n";
    print_usage();
    exit $ERRORS{"UNKNOWN"};
  }

  # SNMP version checks
  if (!defined($o_community) && (!defined($o_login) || !defined($o_passwd))) {
    print "Put snmp login info!\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
  if ((defined($o_login)||defined($o_passwd)) && (defined($o_community)||defined($o_version2))) {
    print "Can't mix snmp v1,2c,3 protocols!\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
  if (defined($v3protocols)) {
    if (!defined($o_login)) {
      print "Put snmp V3 login info with protocols!\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
    }
    my @v3proto = split(/,/,$v3protocols);
    if ((defined($v3proto[0])) && ($v3proto[0] ne "")) { $o_authproto=$v3proto[0]; }
    if (defined($v3proto[1])) { $o_privproto=$v3proto[1]; }
    if ((defined($v3proto[1])) && (!defined($o_privpass))) {
      print "Put snmp V3 priv login info with priv protocols!\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
    }
  }
  if (defined($o_timeout) && (isnnum($o_timeout)||($o_timeout<2)||($o_timeout>60))) {
    print "Timeout must be >1 and <60!\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
  if (!defined($o_timeout)) { $o_timeout=5; }

  if (defined($o_highperf) && (!defined($o_version2) && defined($o_community))) {
    print "Can't get 64 bit counters with snmp version 1\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
  if (defined($o_highperf)) {
    if (eval "require bigint") { use bigint; }
    else { print "Need bigint module for 64 bit counters\n"; exit $ERRORS{"UNKNOWN"}; }
  }
  if (defined($o_perfe) && !defined($o_perf)) {
    print "Cannot output error without -f option!\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
  if (defined($o_weather) && !defined($o_perf)) {
    print "Cannot output weathermap data without -f option!\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
  if (defined($o_perfr) && defined($o_perfp)) {
    print "-Y and -y options are exclusives\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
  if ((defined($o_perfr)||defined($o_perfp)) && !defined($o_checkperf)) {
    print "Cannot put -Y or -y without perf check option (-k)\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
  if (defined($o_checkperf)) {
    @o_warn = split(/,/,$o_warn_opt);
    if (defined($o_ext_checkperf) && (($#o_warn<5)||($#o_warn>6))) {
      print "6 or 7 warning levels for extended checks\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
    }
    if (!defined($o_ext_checkperf) && ($#o_warn != 1)) {
      print "2 warning levels for bandwidth checks\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
    }
    @o_crit = split(/,/,$o_crit_opt);
    if (defined($o_ext_checkperf) && (($#o_crit<5)||($#o_crit>6))) {
      print "6 or 7 critical levels for extended checks\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
    }
    if (!defined($o_ext_checkperf) && ($#o_crit != 1)) {
      print "2 critical levels for bandwidth checks\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
    }
    for (my $i=0;$i<=$#o_warn;$i++) {
      if ($i != 6) {
        if (($o_crit[$i]!=0) && ($o_warn[$i]>$o_crit[$i])) {
          print "Warning must be < Critical\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
        }
      } else {
        if (($o_crit[$i]!=0) && ($o_warn[$i]<$o_crit[$i])) {
          print "Warning must be > Critical\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
        }
      }
    }
    if ((defined($o_meg)&&defined($o_gig))||(defined($o_meg)&&defined($o_prct))||(defined($o_gig)&&defined($o_prct))) {
      print "-M -G and -u are exclusives\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
    }
  }
  if (defined($o_octetlength) && (isnnum($o_octetlength)||$o_octetlength>65535||$o_octetlength<484)) {
    print "octet length must be <65535 and >484\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
  if (defined($o_ignore_admindown) && defined($o_admin)) {
    print "ERROR: --ign-admindown and -a are mutually exclusive.\n"; print_usage(); exit $ERRORS{"UNKNOWN"};
  }
}

########## MAIN #######

check_options();

if (defined($o_timeout)) {
  verb("Alarm in $o_timeout seconds");
  alarm($o_timeout);
}
$SIG{'ALRM'} = sub {
  print "No answer from host $o_host:$o_port\n";
  exit $ERRORS{"UNKNOWN"};
};

# Connect
my ($session,$error);
if (defined($o_login) && defined($o_passwd)) {
  if (!defined($o_privpass)) {
    verb("SNMPv3 AuthNoPriv login : $o_login, $o_authproto");
    ($session,$error) = Net::SNMP->session(
      -hostname=>$o_host,-version=>'3',-port=>$o_port,
      -username=>$o_login,-authpassword=>$o_passwd,-authprotocol=>$o_authproto,
      -timeout=>$o_timeout,-domain=>$o_domain);
  } else {
    verb("SNMPv3 AuthPriv login : $o_login, $o_authproto, $o_privproto");
    ($session,$error) = Net::SNMP->session(
      -hostname=>$o_host,-version=>'3',-username=>$o_login,-port=>$o_port,
      -authpassword=>$o_passwd,-authprotocol=>$o_authproto,
      -privpassword=>$o_privpass,-privprotocol=>$o_privproto,
      -timeout=>$o_timeout,-domain=>$o_domain);
  }
} else {
  if (defined($o_version2)) {
    verb("SNMP v2c login");
    ($session,$error) = Net::SNMP->session(
      -hostname=>$o_host,-version=>2,-community=>$o_community,
      -port=>$o_port,-timeout=>$o_timeout,-domain=>$o_domain);
  } else {
    verb("SNMP v1 login");
    ($session,$error) = Net::SNMP->session(
      -hostname=>$o_host,-community=>$o_community,
      -port=>$o_port,-timeout=>$o_timeout,-domain=>$o_domain);
  }
}

if (!defined($session)) {
  printf("ERROR opening session: %s.\n",$error);
  exit $ERRORS{"UNKNOWN"};
}

if (defined($o_octetlength)) {
  my $oct_resultat = $session->max_msg_size($o_octetlength);
  if (!defined($oct_resultat)) {
    printf("ERROR: Session settings : %s.\n",$session->error);
    $session->close; exit $ERRORS{"UNKNOWN"};
  }
}

# Get description table
my $query_table = $descr_table;
if (defined($o_use_ifalias) && defined($o_use_ifname)) {
  printf("ERROR: Options -N and -A are exclusive.\n");
  $session->close; exit $ERRORS{"UNKNOWN"};
}
if (defined($o_use_ifname))  { $query_table = $name_table; }
if (defined($o_use_ifalias)) { $query_table = $alias_table; }

my $resultat = $session->get_table(Baseoid => $query_table);
if (!defined($resultat)) {
  printf("ERROR: Description table : %s.\n",$session->error);
  $session->close; exit $ERRORS{"UNKNOWN"};
}

my (@tindex,@oids,@descr);
my (@oid_perf,@oid_perf_outoct,@oid_perf_inoct,@oid_perf_inerr,
    @oid_perf_outerr,@oid_perf_indisc,@oid_perf_outdisc) = (undef)x7;
my (@oid_speed,@oid_speed_high);
my $num_int = 0;

if (defined($o_highperf)) {
  $out_octet_table = $out_octet_table_64;
  $in_octet_table  = $in_octet_table_64;
}

my $admin_status_table;
if (defined($o_ignore_admindown)) {
  $admin_status_table = $session->get_table(Baseoid => $admin_table);
  if (!defined($admin_status_table)) {
    printf("ERROR: Admin status table : %s.\n",$session->error);
    $session->close; exit $ERRORS{"UNKNOWN"};
  }
}

my $interfaces_aliases;
if (defined($o_ignore_emptyalias)) {
  $interfaces_aliases = $session->get_table(Baseoid => $alias_table);
  if (!defined($interfaces_aliases)) {
    printf("ERROR: Alias status table : %s.\n",$session->error);
    $session->close; exit $ERRORS{"UNKNOWN"};
  }
}

verb("Filter : $o_descr");
foreach my $key (sort { $$resultat{$a} cmp $$resultat{$b} } keys %$resultat) {
  verb("OID : $key, Desc : $$resultat{$key}");
  my $ignore = 0;
  my $prefix  = $query_table.".";
  my ($ifindex) = $key =~ /$prefix(\d+)$/;

  if (defined($o_ignore_admindown)) {
    my $index    = $admin_table.".".$ifindex;
    my $admstatus = $$admin_status_table{$index};
    $ignore = 1 if ($admstatus == 2);
  }
  if (defined($o_ignore_emptyalias)) {
    my $index = $alias_table.".".$ifindex;
    my $alias = $$interfaces_aliases{$index};
    $ignore = 1 if ($alias eq "");
  }

  my $test = defined($o_noreg)
    ? $$resultat{$key} eq $o_descr
    : $$resultat{$key} =~ /$o_descr/;

  if ($test && !$ignore) {
    my @oid_list = split(/\./,$key);
    my $int_index = pop(@oid_list);
    if (defined($o_noreg) && ($num_int > 0)) {
      if ($tindex[$num_int-1] < $int_index) { $num_int=0; }
    }
    if (!defined($o_noreg) || ($num_int==0)) {
      $tindex[$num_int] = $int_index;
      $descr[$num_int]  = $$resultat{$key};
      $descr[$num_int]  =~ s/[[:cntrl:]]//g;
      $oids[$num_int]   = defined($o_admin)
        ? $admin_table.".".$tindex[$num_int]
        : $oper_table.$tindex[$num_int];
      if (defined($o_perf) || defined($o_checkperf)) {
        $oid_perf_inoct[$num_int]  = $in_octet_table.$tindex[$num_int];
        $oid_perf_outoct[$num_int] = $out_octet_table.$tindex[$num_int];
        $oid_speed[$num_int]       = $speed_table.$tindex[$num_int];
        $oid_speed_high[$num_int]  = $speed_table_64.$tindex[$num_int];
        if (defined($o_ext_checkperf) || defined($o_perfe)) {
          $oid_perf_indisc[$num_int]  = $in_discard_table.$tindex[$num_int];
          $oid_perf_outdisc[$num_int] = $out_discard_table.$tindex[$num_int];
          $oid_perf_inerr[$num_int]   = $in_error_table.$tindex[$num_int];
          $oid_perf_outerr[$num_int]  = $out_error_table.$tindex[$num_int];
        }
      }
      verb("Name : $descr[$num_int], Index : $tindex[$num_int]");
      $num_int++;
    }
  }
}

if ($num_int == 0) {
  print "ERROR : Unknown interface $o_descr\n";
  exit $ERRORS{"UNKNOWN"};
}

my $result = undef;
if (defined($o_perf) || defined($o_checkperf)) {
  @oids = (@oids,@oid_perf_outoct,@oid_perf_inoct,@oid_speed);
  if (defined($o_highperf))                          { @oids = (@oids,@oid_speed_high); }
  if (defined($o_ext_checkperf)||defined($o_perfe))  { @oids = (@oids,@oid_perf_inerr,@oid_perf_outerr,@oid_perf_indisc,@oid_perf_outdisc); }
}

while (my @oids_part = splice(@oids,0,$snmp_splice_size)) {
  my $result_part = $session->get_request(Varbindlist => \@oids_part);
  if (!defined($result_part)) {
    printf("ERROR: Status/statistics table : %s.\n ",$session->error);
    $session->close; exit $ERRORS{"UNKNOWN"};
  }
  $result = defined($result) ? {%$result,%$result_part} : $result_part;
}
$session->close;

my $num_ok = 0;
my (@checkperf_out,@checkperf_out_raw);
my $temp_file_name;
my ($return,@file_values) = (undef,undef);
my $n_rows = 0;
my $n_items_check = (defined($o_ext_checkperf)) ? 7 : 3;
my $timenow     = time;
my $trigger     = $timenow - ($o_delta - ($o_delta/10));
my $trigger_low = $timenow - 3*$o_delta;
my ($old_value,$old_time) = undef;
my $speed_unit = undef;
my $speed_real = undef;
my $ok_val     = defined($o_inverse) ? 2 : 1;
my $final_status = 0;
my ($print_out,$perf_out) = (undef,undef);

for (my $i=0;$i<$num_int;$i++) {
  $print_out .= "\n" if defined($print_out);
  my $usable_data = 1;
  my $int_status = defined($o_admin)
    ? $$result{$admin_table.".".$tindex[$i]}
    : $$result{$oper_table.$tindex[$i]};

  $perf_out .= " " if (defined($perf_out) && $int_status==2);

  if (defined($o_checkperf) && $int_status==1) {
    $temp_file_name = $descr[$i];
    $temp_file_name =~ s/[ ;\/]/_/g;
    $temp_file_name = $o_base_dir.$o_host.".".$o_port.".".$temp_file_name;

    my @ret_array = read_file($temp_file_name,$n_items_check);
    $return  = shift(@ret_array);
    $n_rows  = shift(@ret_array);
    if ($n_rows != 0) { @file_values = @ret_array; }
    verb("File read returns : $return with $n_rows rows");

    if ($$result{$oid_speed[$i]} == 4294967295) {
      if (!defined($o_highperf) && (defined($o_prct)||defined($o_perfs)||defined($o_perfp))) {
        print "Cannot get interface speed with standard MIB, use highperf mib (-g) : UNKNOWN\n";
        exit $ERRORS{"UNKNOWN"};
      }
      if (defined($$result{$oid_speed_high[$i]}) && $$result{$oid_speed_high[$i]}!=0) {
        $speed_real = $$result{$oid_speed_high[$i]} * 1000000;
      } else {
        print "Cannot get interface speed using highperf mib : UNKNOWN\n";
        exit $ERRORS{"UNKNOWN"};
      }
    } else { $speed_real = $$result{$oid_speed[$i]}; }
    verb("Interface speed : $speed_real");

    if ($return == 0) {
      my $j = $n_rows-1;
      @checkperf_out     = undef;
      @checkperf_out_raw = undef;
      do {
        if ($file_values[$j][0] < $trigger) {
          if ($file_values[$j][0] > $trigger_low) {
            my $speed_metric = undef;
            if (defined($o_prct)) {
              $speed_metric = $speed_real/800; $speed_unit="%";
            } else {
              if (defined($o_kbits)) {
                if    (defined($o_meg)) { $speed_metric=125000;    $speed_unit="Mbps"; }
                elsif (defined($o_gig)) { $speed_metric=125000000; $speed_unit="Gbps"; }
                else                   { $speed_metric=125;        $speed_unit="Kbps"; }
              } else {
                if    (defined($o_meg)) { $speed_metric=1048576;    $speed_unit="MBps"; }
                elsif (defined($o_gig)) { $speed_metric=1073741824; $speed_unit="GBps"; }
                else                   { $speed_metric=1024;        $speed_unit="KBps"; }
              }
            }
            my $overfl_mod = defined($o_highperf) ? 18446744073709551616 : 4294967296;
            my $overfl = ($$result{$oid_perf_inoct[$i]} >= $file_values[$j][1]) ? 0 : $overfl_mod;
            $checkperf_out_raw[0] = (($overfl+$$result{$oid_perf_inoct[$i]}-$file_values[$j][1])
                                      /($timenow-$file_values[$j][0]));
            $checkperf_out[0] = $checkperf_out_raw[0]/$speed_metric;
            $overfl = ($$result{$oid_perf_outoct[$i]} >= $file_values[$j][2]) ? 0 : $overfl_mod;
            $checkperf_out_raw[1] = (($overfl+$$result{$oid_perf_outoct[$i]}-$file_values[$j][2])
                                      /($timenow-$file_values[$j][0]));
            $checkperf_out[1] = $checkperf_out_raw[1]/$speed_metric;
            if (defined($o_ext_checkperf)) {
              $checkperf_out[2] = (($$result{$oid_perf_inerr[$i]}-$file_values[$j][3]) /($timenow-$file_values[$j][0]))*60;
              $checkperf_out[3] = (($$result{$oid_perf_outerr[$i]}-$file_values[$j][4])/($timenow-$file_values[$j][0]))*60;
              $checkperf_out[4] = (($$result{$oid_perf_indisc[$i]}-$file_values[$j][5])/($timenow-$file_values[$j][0]))*60;
              $checkperf_out[5] = (($$result{$oid_perf_outdisc[$i]}-$file_values[$j][6])/($timenow-$file_values[$j][0]))*60;
            }
          }
        }
        $j--;
      } while (($j>=0) && (!defined($checkperf_out[0])));
    }

    $file_values[$n_rows][0] = $timenow;
    $file_values[$n_rows][1] = $$result{$oid_perf_inoct[$i]};
    $file_values[$n_rows][2] = $$result{$oid_perf_outoct[$i]};
    if (defined($o_ext_checkperf)) {
      $file_values[$n_rows][3] = $$result{$oid_perf_inerr[$i]};
      $file_values[$n_rows][4] = $$result{$oid_perf_outerr[$i]};
      $file_values[$n_rows][5] = $$result{$oid_perf_indisc[$i]};
      $file_values[$n_rows][6] = $$result{$oid_perf_outdisc[$i]};
    }
    $n_rows++;
    $return = write_file($temp_file_name,$n_rows,$n_items_check,@file_values);
    verb("Write file returned : $return");

    # ── UDT: friendly port name ──────────────────────────────────
    my $friendly_name = $descr[$i];
    if    ($friendly_name =~ /Port:\s*(\d+)\s+10G/i)     { $friendly_name = "Port $1 (10G)"; }
    elsif ($friendly_name =~ /Port:\s*(\d+)\s+Gigabit/i) { $friendly_name = "Port $1 (1G)";  }
    elsif ($friendly_name =~ /Port:\s*(\d+)/i)            { $friendly_name = "Port $1";       }
    # ─────────────────────────────────────────────────────────────

    if (defined($o_short)) {
      my $sd = ($o_short<0) ? substr($friendly_name,$o_short) : substr($friendly_name,0,$o_short);
      $print_out .= sprintf("%s: %s",$sd,$status{$int_status});
    } else {
      $print_out .= sprintf("%s: %s",$friendly_name,$status{$int_status});
    }

    if ($return != 0) {
      $final_status=3;
      $print_out .= " !!Unable to write file ".$temp_file_name."!! ";
    }

    if (defined($checkperf_out[0])) {
      # ── UDT: user-friendly bandwidth display ──────────────────
      my $in_str  = sprintf("%.1f%s", $checkperf_out[0], $speed_unit);
      my $out_str = sprintf("%.1f%s", $checkperf_out[1], $speed_unit);
      if    (($o_crit[0]!=0) && ($checkperf_out[0]>$o_crit[0])) { $final_status=2; $in_str="CRIT $in_str"; }
      elsif (($o_warn[0]!=0) && ($checkperf_out[0]>$o_warn[0])) { $final_status=($final_status==2)?2:1; $in_str="WARN $in_str"; }
      if    (($o_crit[1]!=0) && ($checkperf_out[1]>$o_crit[1])) { $final_status=2; $out_str="CRIT $out_str"; }
      elsif (($o_warn[1]!=0) && ($checkperf_out[1]>$o_warn[1])) { $final_status=($final_status==2)?2:1; $out_str="WARN $out_str"; }
      if (defined($o_ext_checkperf)) {
        for (my $l=2;$l<6;$l++) {
          verb("Interface $i, check $l : $checkperf_out[$l]");
          if    (($o_crit[$l]!=0) && ($checkperf_out[$l]>$o_crit[$l])) { $final_status=2; }
          elsif (($o_warn[$l]!=0) && ($checkperf_out[$l]>$o_warn[$l])) { $final_status=($final_status==2)?2:1; }
        }
      }
      $print_out .= " (IN:$in_str OUT:$out_str)";
      # ──────────────────────────────────────────────────────────

      # ── UDT: perfdata in checkperf (-k) mode ──────────────────
      if (defined($o_perf)) {
        my $label = $descr[$i];
        $label =~ s/[ :\/()]/\_/g;
        $label =~ s/__+/_/g;
        $label =~ s/^_|_$//g;
        $perf_out = "" unless defined($perf_out);
        $perf_out .= sprintf("'%s_in'=%.1f%s;%.1f;%.1f;; '%s_out'=%.1f%s;%.1f;%.1f;; ",
            $label, $checkperf_out[0], $speed_unit, $o_warn[0], $o_crit[0],
            $label, $checkperf_out[1], $speed_unit, $o_warn[1], $o_crit[1]);
      }
      # ──────────────────────────────────────────────────────────

    } else {
      $print_out .= " No usable data on file ($n_rows rows) ";
      $final_status=3; $usable_data=0;
    }

  } else {
    my $fn = $descr[$i];
    if    ($fn =~ /Port:\s*(\d+)\s+10G/i)     { $fn = "Port $1 (10G)"; }
    elsif ($fn =~ /Port:\s*(\d+)\s+Gigabit/i) { $fn = "Port $1 (1G)";  }
    elsif ($fn =~ /Port:\s*(\d+)/i)            { $fn = "Port $1";       }
    if (defined($o_short)) {
      my $sd = ($o_short<0) ? substr($fn,$o_short) : substr($fn,0,$o_short);
      $print_out .= sprintf("%s: %s",$sd,$status{$int_status});
    } else {
      $print_out .= sprintf("%s: %s",$fn,$status{$int_status});
    }
  }

  # Status check
  if (!defined($o_dormant) && $int_status==5) { $int_status=2; }
  if (defined($o_down)     && $int_status==2) { $int_status=1; }

  if ($int_status == $ok_val) {
    $num_ok++;
  } else {
    if (!defined($o_inverse)) {
      $final_status = ($final_status==2)?2:2;
    } else {
      $final_status = ($final_status==2)?2:2;
    }
  }

  # Perfdata (non-checkperf mode)
  if ((defined($o_perf)) && (!defined($o_checkperf))) {
    if ($int_status==1) {
      my $label = $descr[$i];
      $label =~ s/[ :\/()]/\_/g;
      $label =~ s/__+/_/g;
      $label =~ s/^_|_$//g;

      my $in_val  = $$result{$oid_perf_inoct[$i]}  // 0;
      my $out_val = $$result{$oid_perf_outoct[$i]} // 0;

      $perf_out .= sprintf("'%s_in'=%sc '%s_out'=%sc ",$label,$in_val,$label,$out_val);

      if (defined($o_perfe)) {
        my $inerr  = $$result{$oid_perf_inerr[$i]}  // 0;
        my $outerr = $$result{$oid_perf_outerr[$i]} // 0;
        my $indisc = $$result{$oid_perf_indisc[$i]} // 0;
        my $outdisc= $$result{$oid_perf_outdisc[$i]}// 0;
        $perf_out .= sprintf("'%s_inerr'=%s '%s_outerr'=%s '%s_indisc'=%s '%s_outdisc'=%s ",
                             $label,$inerr,$label,$outerr,$label,$indisc,$label,$outdisc);
      }
      if (defined($o_perfs)) {
        my $spd = $$result{$oid_speed[$i]} // 0;
        $perf_out .= sprintf("'%s_speed'=%s ",$label,$spd);
      }
    }
  }
}

# ── UDT: perfonly — override final status to OK ──────────────
if (defined($o_perfonly)) {
  $final_status = 0;
}
# ─────────────────────────────────────────────────────────────

my $exit_msg;
if    ($final_status==0) { $exit_msg="OK"; }
elsif ($final_status==1) { $exit_msg="WARNING"; }
elsif ($final_status==2) { $exit_msg="CRITICAL"; }
else                     { $exit_msg="UNKNOWN"; }

if (!defined($perf_out)) { $perf_out=""; }

if (defined($o_perf) || defined($o_checkperf)) {
  printf "%s: %s |%s\n",$exit_msg,$print_out,$perf_out;
} else {
  printf "%s: %s\n",$exit_msg,$print_out;
}

exit $ERRORS{$exit_msg};
