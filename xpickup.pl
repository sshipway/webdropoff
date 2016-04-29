#!/usr/bin/perl -w
#
# Perl code for pickup utility
#
# Steve Shipway 2007, Univeristy of Auckland
#
# This picks up a file from the web dropoff, and decrypts it using the Private Key.
# This is a TK application, which should be compiled using Perl2EXE and activeperl 5.8
# Requires the Crypt:: modules, which cannot be obtained from Activestate (but see
# their website for instructions on other repositories which carry them)
#
# You can compile up with perl2exe from http://www.indigostar.com/ but you will need
# to obtain and install Crypt::SSLeay, Crypt::CBC, Crypt::RSA and Crypt::Blowfish first
# Also Net::SSLeay and IO::Socket::SSL if using perl2exe.
# These cryptographic modules can be obtained from University of Winnipeg since USA
# makes life awkward for the rest of us (shows how pointless their export rules are)
#
# Dont forget to set the URL of the pickup script first before you compile!

# We need to explicitly include all the SSL modules else perl2exe will not pick them
# up, and then at run time LWP will think we do not have SSL and hence no https

#############################################################
# Default URL of pickup script.  Required.
my($PICKUP) = "https://webdropoff.auckland.ac.nz/cgi-bin/ppickup";
# Username/password (basic authentication) for pickup URL
my($USERNAME,$PASSWORD) = ("","");
# Temporary workspace
my($TMPDIR) = "C:/temp";
# Timeout for HTTP
my($TIMEOUT) = 10;
# This script version
my($VERSION) = "2.1";
#############################################################

use LWP;
use File::Basename;
use Crypt::CBC;
use Crypt::RSA;
use Crypt::RSA::ES::OAEP;
use Crypt::SSLeay;
use Crypt::Blowfish;
# Tk modules: for perl2exe we have to specify them all
use Tk;
use Tk::Dialog;
use Tk::DialogBox;
use Tk::LabEntry;
use Tk::BrowseEntry;
use Tk::Menubutton;
use Tk::Text;

# Special things for perl2exe
#perl2exe_include utf8
#perl2exe_include "unicore/lib/gc_sc/Word.pl"
#perl2exe_include "unicore/lib/gc_sc/Digit.pl"
#perl2exe_include "unicore/lib/gc_sc/SpacePer.pl"
#perl2exe_include "unicore/lib/gc_sc/Uppercas.pl"
#perl2exe_include "unicore/To/Lower.pl"
#perl2exe_bundle  "SSLeay32.dll"
#perl2exe_bundle  "libeay32.dll"
#
#perl2exe_info CompanyName=University of Auckland
#perl2exe_info FileVersion=1.0
#perl2exe_info ProductVersion=1.0
#perl2exe_info ProductName=Web Pickup
#perl2exe_info LegalCopyright=Copyright University of Auckland 2007

# If compiling using PAR, then use the command line
# pp -a SSLeay32.dll -a libeay32.dll --gui -v -o xpickup.exe xpickup.pl
# Note that a PAR compiled script can take up to 10 seconds to start up, but
# perl2exe is almost immediate.  Hmm.

#############################################################
# Registry manipulation stuff so we can store updates.
my $Registry;
use Win32::TieRegistry 0.20 (
    TiedRef => \$Registry,  Delimiter => "/",  ArrayValues => 1,
    SplitMultis => 1,  AllowLoad => 1,
    qw( REG_SZ REG_EXPAND_SZ REG_DWORD REG_BINARY REG_MULTI_SZ
        KEY_READ KEY_WRITE KEY_ALL_ACCESS ),
);
#############################################################
# messy stuff for LWP agent overrides
{
	package MyAgent;
	@ISA = qw(LWP::UserAgent);
	sub new {
		my $self = LWP::UserAgent::new(@_);
		$self->agent("XPickup/$VERSION");
		$self;
	}
	sub get_basic_credentials {return($USERNAME,$PASSWORD); }
}
use strict;
my($keylen,$ivlen,$ciphername) = (56,8,"Blowfish");
##############################################################
# Global TK variables
my($main,$menubar);
my($bloadkey,$bdecrypt,$bexit);
my($fcode,$ffilename);
##############################################################
# Global utility variables
my($ua) = new MyAgent;
$ua->agent("XPickup/$VERSION");
$ua->timeout($TIMEOUT);
push @{ $ua->requests_redirectable }, "POST";
#my($COOKIES) = HTTP::Cookies->new;
#$ua->cookie_jar($COOKIES);
my($privatekey);
##############################################################
# Subroutines

sub doalert($) # standard alert popup window
{
	my($msg) = $_[0];
	chomp $msg;
	if($main) {
		$main->Dialog(-title=>"Error",-text=>$msg,-bitmap=>"error",-buttons=>['Ok'])->Show('-global');
	} else {
		print STDERR "\nERROR: $msg\n";
	}
}
sub doinfo($) # standard alert popup window
{
	my($msg) = $_[0];
	chomp $msg;
	if($main) {
		$main->Dialog(-title=>"Info",-text=>$msg,-bitmap=>"info",-buttons=>['Ok'])->Show('-global');
	} else {
		print STDERR "\nINFO: $msg\n";
	}
}

sub quit_it { # Obvious
	$main->destroy;
	exit;
}  

sub prompt_string {
	my(@fields) = @_;
	my( $title, $prompt, $prefix, $default );
	my( $rv ) = "";
	my(@rv,@fld,@def);
	my($over,$textf,$text,$butf,$retval,$yes,$no,$field,$fieldf);

	$title = shift @fields;
	$prompt = shift @fields;
	$over=$main->Toplevel('-title'=>$title);
#	$over->geometry("+".int($main->width/2)."+".int($main->height/2));
	$over->geometry("+".int($main->x+($main->width*0.1))."+".int($main->y+($main->height*0.1)));
	$over->transient($main);
	$over->grab;
	$textf=$over->Frame->pack;
	$text=$textf->Label('-text' => $prompt)->pack('-side' => 'left');
	$fieldf = $over->Frame->pack;

	while( @fields ) {
		$prefix = shift @fields;
		$default = shift @fields;
		$text=$fieldf->Label('-text' => $prefix)->pack(-side=>'left');
		$field = $fieldf->Text(
			'-wrap'	=> 'none',
			'-height' => 1,
			'-width' => 25
		)->pack('-side'=>'left');
		$field->insert('end',$default);
		push @fld, $field;
		push @def, $default;
	}

	$butf=$over->Frame->pack;
	$yes=$butf->Button(
		'-text'		=> "OK",
		'-command'	=> sub{ $retval = 1 }
	)->pack('-side' => 'left');
	$no=$butf->Button(
		'-text'		=> "Cancel",
		'-command'	=> sub{ $retval = 0 }
	)->pack('-side' => 'left');
	$over->waitVariable(\$retval);
	$over->grab;

	if(!$retval) {
		$over->destroy;
		return ();
	}
	while( @fld ) {
		$field = shift @fld; $default = shift @def;
		$rv = $field->get('1.0','end');
		$rv = $default if(!$rv);
		chomp $rv;
		push @rv, $rv;
	}
	$over->destroy;
	return (@rv);
}
sub readregistry() {
	my($p);
	$p = $Registry->{"LMachine/Software/Cheshire Cat/XPickup/pickupurl"};
	$PICKUP = $p if($p and $p=~/^https?\/\/.*\//);
}
sub editregistry() {
	my($k,$v);
	my(@resp,$url);

	$k = $Registry->{"LMachine/Software/Cheshire Cat/XPickup/"};
	if(!$k) {
		$k = $Registry->{"LMachine/Software/"};
		return if(!$k);
		$k = $k->CreateKey("Cheshire Cat");
		return if(!$k);
		$k = $k->CreateKey("XPickup");
		return if(!$k);
	}
	# Now we have a handle on the registry part...
	$k->SetValue('pickupurl',$PICKUP,REG_SZ);

	# Prompt user for new URL
	@resp = prompt_string("Pickup URL","Enter URL of pickup script on WebDropoff server",
		"URL:",$PICKUP);
	$url = $resp[0];

	# Check validity of URL
	if($url !~ /^https?:\/\/.*\//) {
		doalert("Bad format of URL: must be http:// or https://");
		return;
	}	
	# Save new value.
	$PICKUP = $url;
	$k->SetValue('pickupurl',$PICKUP,REG_SZ);
}

sub about { # Show about
	my($label,$about,$but);
	my $MSG="XPickup - pick up files from webdropoff,\n"
	       ."and decrypt using public key system.\n";

	$MSG.="\nAuthor:  Steve Shipway, 2007\n";

	$about=$main->Toplevel('-title'=>"About XPickup");
	$about->geometry("+".int($main->x+($main->width*0.1))."+".int($main->y+($main->height*0.1)));
	$about->transient($main);
	$about->resizable(0,0);
	$about->grab;
	$label=$about->Label(
		'-text'		=> "XPickup v$VERSION\n\n$MSG",
		'-justify'	=> 'left'
	)->pack('-padx'=>5,'-pady'=>5,'-expand'=>1);
	$but=$about->Button(
		'-text'		=> ("OK"),
		'-command'	=> sub{$about->grabRelease;$about->destroy},
	)->pack('-pady'=>10);
}

sub enablebuttons {
	$menubar->entryconfigure("Decrypt",'-state' => 'normal');
	$menubar->entryconfigure("Load Key",'-state' => 'normal');
	$bloadkey->configure('-state'=>'normal');
	$bdecrypt->configure('-state'=>'normal');
}
sub disablebuttons {
	$menubar->entryconfigure("Decrypt",'-state' => 'disabled');
	$menubar->entryconfigure("Load Key",'-state' => 'disabled');
	$bloadkey->configure('-state'=>'disabled');
	$bdecrypt->configure('-state'=>'disabled');
}


sub load_key {
	my(@resp,$filename,$types,$pass);

	# Select key file or cancel
	$types = [["Key files",".key"],["All Files","*"]];
	$filename = $main->getOpenFile(-defaultextension=>'.key',-filetypes=>$types,
		-title=>"Select private key");
	if(!$filename) {
		doinfo("Cancelled.");
		return;
	}
	@resp = prompt_string("Enter Password","Enter password for Private Key file",
		"Password:","");
	$pass = $resp[0];

	# load in privatekey
	$privatekey = new Crypt::RSA::Key::Private(KF=>'SSH',Filename=>$filename);
	if(!$privatekey) {
		doalert("Cannot load RSA private key");
		return;
	}
	if($pass) { 
		if($privatekey->reveal(Password=>$pass)) {
			doalert("Cannot decrypt RSA private key");
			enablebuttons; return;		
		}
		doinfo("Decrypted private key");
	}

	# enable Decrypt button and other fields
	doinfo("Private key loaded in successfully");
	enablebuttons;
}
sub save_key {
	my($newfilename);

	$newfilename = $main->getSaveFile(
		-initialfile=>"private.key",
		-title=>"Select save destiniation",
	);
	if($newfilename) {
		$privatekey->write(Filename=>$newfilename);
	}

}

sub browse_files {
	my($filename);
	# select filename using standard open dialog or cancel
	$filename = $main->getOpenFile('-title'=>"Select file");
	
	# load into field
	if($filename) {	$ffilename->Contents($filename);}

}

# fetch specified file from website: param: code/pass
sub fetchfile($) {
	my($codepass) = $_[0];
	my($code,$pass);
	my($req,$res);
	my($tmpfile);
	my($fname) = "";

	if( $codepass =~ /([a-f0-9]{32})[\/\.](\d+)/ ) { ($code,$pass)=($1,$2); } 
	else { doalert "Code not in correct format."; return ("",""); }

	# Already set up useragent.
	$req = HTTP::Request->new(GET=>"$PICKUP/$code/$pass?raw=1");
#	$req->content_type("application/x-www-form-urlencoded");
#	$req->content("hash=$code\&passcode=$pass");

	$res = $ua->request($req);
	if(!$res) {
		doalert("Unable to pick up file $code/$pass");
		return ("","");
	}
	if($res->code != 200) {
		doalert("Received response code ".$res->code." for $code/$pass:\n"
			.$res->message);
		return ("","");
	}
	$tmpfile = "$TMPDIR/tmpfile.$$.enc";
	open OUT,">$tmpfile" or do {
		doalert "Unable to write to temporary file $tmpfile: $!";
		return ("","");
	};
	binmode OUT;
	print OUT $res->content;
	close OUT;

	$fname = $res->header('Content-Disposition');
	if($fname =~ /filename="(.*)"/ ) { $fname = $1; } else { $fname = ""; }
	# return temp filename, or null
	return ($tmpfile,$fname);
}


sub decrypt {
	my($newfilename,$filename,$code,@resp);
	my($data,$enc,$rsa,$key,$iv,$cipher);

	$newfilename = "";
	$filename = $ffilename->get('1.0','end'); chomp $filename;
	$code = $fcode->get('1.0','end'); chomp $code;

	# disable decrypt button and load key button, make cursor hourglass
	disablebuttons;

	# fetch file if necessary, cancel if fail
	if($code) {	
		($filename,$newfilename) = fetchfile($code);
		if(!$filename) {
			doalert("Unable to collect file [$code].");
			enablebuttons;
			return;
		}
	} 
	if(!-r $filename) {
		doalert("Unable to read file $filename");
		enablebuttons;
		return;
	}

	# Prompt for save-as or cancel
	$newfilename = $main->getSaveFile(
#		-filetypes=>[['All files','*']],
		-initialfile=>($newfilename?$newfilename:basename($filename)),
		-title=>"Select save destiniation",
#		-message=>"Select where to save the decrypted file to"
	);
	if(!$newfilename) {
		doinfo("Decryption cancelled");
		enablebuttons;
		return;
	}

	# decrypt file
	open ENC,"<$filename" or do {
		doalert("Unable to read temporary encrypted file: $!");
		enablebuttons; return;
	};
	binmode ENC;
	# first 128 bytes are encrypted $key.$iv for onetime key
	if(read (ENC,$enc,128)	!= 128 ) {
		doalert("Could not read entire encryption key: decryption failed");
		enablebuttons; return;
	}
	# decrypt temp key with publickey
	$rsa = new Crypt::RSA(ES=>'OAEP',KF=>'SSH');
	if(!$rsa) {
		doalert("Could not create RSA object for decryption");
		enablebuttons; return;
	}
#	doinfo($enc);
	if( !$enc or !$privatekey ) {
		doalert("Unexpected problem with RSA decryption");
		enablebuttons; return;
	}
	$data = $rsa->decrypt(Cyphertext=>$enc,Key=>$privatekey);#,Armour=>1);
	if( !$data ) {
		doalert("Could not decrypt one-time key: do you have the right Private Key? ".$rsa->errstr);
		enablebuttons; return;		
	}
	if( length $data != ($keylen + $ivlen) ) {
		doalert("Could not decrypt one-time key: do you have the right Private Key? Bytes=".(length $data)."!=".($keylen+$ivlen));
		enablebuttons; return;		
	}
	$key = substr $data, 0, $keylen;
	$iv = substr $data, $keylen, $ivlen;
	$cipher = Crypt::CBC->new(-literal_key => 1, 
	    -cipher => $ciphername,
            -key => $key, -iv => $iv, -header => 'none', -keysize => $keylen );
	if(!$cipher) {
		doalert("Decryption problem: Cannot create $ciphername cypher!");
		enablebuttons; return;		
	}
	# save file
	open OUT,">$newfilename" or do {
		doalert("Unable to write decrypted file $newfilename: $!");
		enablebuttons; return;
	};
	binmode OUT;
	$cipher->start('decrypting');
	while ( read ENC,$enc,128 ) { 
#		doinfo("Cypher: ".(unpack "H8",$_));
		$data = $cipher->crypt($enc); 
#		doinfo("Decrypt: ".(unpack "H8",$data));
		print OUT $data;
	}
	print OUT $cipher->finish();
	close ENC;
	close OUT;

	# tell the user its fluffy
	doinfo("Decryption completed.  Anything you still can't understand is therefore your own problem.");

	# enable buttons, popup 'finished' window, reset cursor
	enablebuttons;

}
sub mw_size { # Set MainWindow size
	my $size=0.9;
	my($dx,$dy)=($main->screenwidth,$main->screenheight);
	$dx = $dx > 1024 ? 1024 : $dx;
	$dy = $dy > 768 ? 768 : $dy;
	return int($size*$dx)."x".int($size*$dy)
}
sub init_gui {	# Initialize main widget, menubar, buttons, fields.
	$main = MainWindow->new('-title'	=> 'XPickup v'.$VERSION);
#	$main->geometry(&mw_size);
	$main->protocol('WM_DELETE_WINDOW',\&quit_it);

	# Create menubar
	my $menuframe = $main->Frame(
		'-relief'=> 'raised','-borderwidth' => 2
	)->pack(
		'-side'=>'top', '-anchor'=>"n",'-expand'=>1, '-fill'=>'x'
	);
	$menubar = $menuframe->Menubutton(
		'-tearoff' 	=> 0,
		'-text'		=> ("File"),
		'-underline' 	=> 0 ,
		'-menuitems' 	=> [
			[ Button => ("Load Key"), '-command' => [\&load_key] ],
			[ Button => ("Save Key"), '-command' => [\&save_key] ],
			[ Button => ("Decrypt"), '-command' => [\&decrypt] , '-state'=>'disabled'],
			[ Button => ("Exit"), '-command' => [\&quit_it] ]
		]
	)->pack('-side' => 'left');
	my $toolsmenu = $menuframe->Menubutton(
		'-tearoff' 	=> 0,
		'-text'		=> ("Tools"),
		'-underline' 	=> 0 ,
		'-menuitems' 	=> [
			[ Button => ("Options"), '-command' => [\&editregistry] ]
		]
	)->pack('-side' => 'left');
 	my $aboutb = $menuframe->Button(
		'-text'=> ("About"),'-relief'=> 'flat',	'-command'=> [\&about]
	)->pack('-side' => 'left');

	# Create screen fields and buttons
	my $framea = $main->Frame->pack('-side'=>'top','-expand'=>1,'-fill'=>'x');
	$framea->Label('-text' => "Please select the data to be decrypted"
		)->pack('-side' => 'top','-anchor'=>"nw");
	my $frameaa = $framea->Frame->pack('-side'=>'top','-expand'=>1,'-fill'=>'x');
	$frameaa->Label('-text' => "Code:")->pack('-side' => 'left','-anchor'=>'nw');
	$fcode = $frameaa->Text(
		'-wrap'	=> 'none','-height' => 1,'-width' => 40
	)->pack('-side'=>'left');
#	$fcode->insert('end','');
	$framea->Label('-text' => "- OR -")->pack('-side' => 'top','-anchor'=>'n');
	my $frameab = $framea->Frame->pack('-side'=>'top','-expand'=>1,'-fill'=>'x');
	$frameab->Label('-text' => "File:    ")->pack('-side' => 'left',-anchor=>'sw');
	$ffilename = $frameab->Text(
		'-wrap'	=> 'none','-height' => 1,'-width' => 34
	)->pack('-side'=>'left');
#	$ffilename->insert('end','');
	$frameab->Button('-text' => "Browse",'-command'=>\&browse_files)->pack('-side' => 'left');
	my $bframe = $main->Frame->pack();
	$bloadkey=$bframe->Button(
		'-text'		=> "Load Key",
		'-command'	=> \&load_key
	)->pack('-side' => 'left');
	$bdecrypt=$bframe->Button(
		'-text'		=> "Decrypt",
		'-command'	=> \&decrypt,
		'-state' => "disabled"
	)->pack('-side' => 'left');
	$bexit=$bframe->Button(
		'-text'		=> "Exit",
		'-command'	=> \&quit_it
	)->pack('-side' => 'left');
}

###############################################################
# Main

readregistry();
init_gui();
MainLoop;
exit(0);