#!/usr/bin/perl

# input is 1st argument or 'codegen/codegen.out.xml'
# 2nd arg is either 'linux' or 'windows' ; for osx use linux

use strict;
use warnings;

my $input = $ARGV[0] or die 'need path to codegen.out.xml';
my $target_class = 'unit';
my $os = $ARGV[1] or die('os not provided (argv[1])');
if ($os =~ /linux/i or $os =~ /darwin/i) {
    $os = 'linux';
} elsif ($os =~ /windows/i) {
    $os = 'windows';
} else {
    die "Unknown OS: " . $ARGV[1] . "\n";
}

my $arch = $ARGV[2] or die('arch not provided (argv[2])');
if ($arch =~ /64/i) {
    $arch = 64;
} elsif ($arch =~ /32/i) {
    $arch = 32;
} else {
    die "Unknown architecture: " . $ARGV[2] . "\n";
}

# 32 bits on Windows and 32-bit *nix, 64 bits on 64-bit *nix
my $SIZEOF_LONG;
if ($os eq 'windows' || $arch == 32) {
    $SIZEOF_LONG = 4;
} else {
    $SIZEOF_LONG = 8;
}

my $SIZEOF_PTR = ($arch == 64) ? 8 : 4;


use XML::LibXML;

my %global_types;

our $compound_off;
our $compound_pointer;

sub get_sizeof {
    my ($type) = @_;
    my $meta = $type->getAttribute('ld:meta');
    local $compound_off = 0;
    $compound_off = $SIZEOF_PTR if ($meta eq 'class-type');
    my $sz = sizeof($type);
    # see comment is sub sizeof ; but gcc has sizeof(cls) aligned
    $sz = align_field($sz, $SIZEOF_PTR) if $os eq 'linux' and $meta eq 'class-type';
    return $sz;
}

my %align_cache;
my %sizeof_cache;

sub align_field {
    my ($off, $fldalign) = @_;
    my $dt = $off % $fldalign;
    $off += $fldalign - $dt if $dt > 0;
    return $off;
}

sub get_field_align {
    my ($field) = @_;
    my $al = $SIZEOF_PTR;
    my $meta = $field->getAttribute('ld:meta');

    if ($meta eq 'number') {
        $al = sizeof($field);
        # linux aligns int64_t to $SIZEOF_PTR, windows to 8
        # floats are 4 bytes so no pb
        $al = 4 if ($al > 4 and (($os eq 'linux' and $arch == 32) or $al != 8));
    } elsif ($meta eq 'global') {
        $al = get_global_align($field);
    } elsif ($meta eq 'compound') {
        $al = get_compound_align($field);
    } elsif ($meta eq 'static-array') {
        my $tg = $field->findnodes('child::ld:item')->[0];
        $al = get_field_align($tg);
    } elsif ($meta eq 'bytes') {
        $al = $field->getAttribute('alignment') || 1;
    } elsif ($meta eq 'primitive') {
        my $subtype = $field->getAttribute('ld:subtype');
        if ($subtype eq 'stl-fstream' and $os eq 'windows') { $al = 8; }
    }

    return $al;
}

sub get_global_align {
    my ($field) = @_;

    my $typename = $field->getAttribute('type-name');
    return $align_cache{$typename} if $align_cache{$typename};

    my $g = $global_types{$typename};

    my $st = $field->getAttribute('ld:subtype') || '';
    if ($st eq 'bitfield' or $st eq 'enum' or $g->getAttribute('ld:meta') eq 'bitfield-type')
    {
        my $base = $field->getAttribute('base-type') || $g->getAttribute('base-type') || 'uint32_t';
        print "$st type $base\n" if $base !~ /int(\d+)_t/;
        # dont cache, field->base-type may differ
        return $1/8;
    }

    my $al = 1;
    for my $gf ($g->findnodes('child::ld:field')) {
        my $fld_al = get_field_align($gf);
        $al = $fld_al if $fld_al > $al;
    }
    $align_cache{$typename} = $al;

    return $al;
}

sub get_compound_align {
    my ($field) = @_;

    my $st = $field->getAttribute('ld:subtype') || '';
    if ($st eq 'bitfield' or $st eq 'enum')
    {
        my $base = $field->getAttribute('base-type') || 'uint32_t';
        if ($base eq 'long') {
            return $SIZEOF_LONG;
        }
        print "$st type $base\n" if $base !~ /int(\d+)_t/;
        return $1/8;
    }

    my $al = 1;
    for my $f ($field->findnodes('child::ld:field')) {
        my $fal = get_field_align($f);
        $al = $fal if $fal > $al;
    }

    return $al;
}

sub sizeof {
    my ($field) = @_;
    my $meta = $field->getAttribute('ld:meta');

    if ($meta eq 'number') {
        if ($field->getAttribute('ld:subtype') eq 'long') {
            return $SIZEOF_LONG;
        }

        return $field->getAttribute('ld:bits')/8;

    } elsif ($meta eq 'pointer') {
        return $SIZEOF_PTR;

    } elsif ($meta eq 'static-array') {
        my $count = $field->getAttribute('count');
        my $tg = $field->findnodes('child::ld:item')->[0];
        return $count * sizeof($tg);

    } elsif ($meta eq 'bitfield-type' or $meta eq 'enum-type') {
        my $base = $field->getAttribute('base-type') || 'uint32_t';
        print "$meta type $base\n" if $base !~ /int(\d+)_t/;
        return $1/8;

    } elsif ($meta eq 'global') {
        my $typename = $field->getAttribute('type-name');
        return $sizeof_cache{$typename} if $sizeof_cache{$typename};

        my $g = $global_types{$typename};
        my $st = $field->getAttribute('ld:subtype') || '';
        if ($st eq 'bitfield' or $st eq 'enum' or $g->getAttribute('ld:meta') eq 'bitfield-type')
        {
            my $base = $field->getAttribute('base-type') || $g->getAttribute('base-type') || 'uint32_t';
            print "$st type $base\n" if $base !~ /int(\d+)_t/;
            return $1/8;
        }

        return sizeof($g);

    } elsif ($meta eq 'class-type' or $meta eq 'struct-type' or $meta eq 'compound') {
        return sizeof_compound($field);

    } elsif ($meta eq 'container') {
        my $subtype = $field->getAttribute('ld:subtype');

        if ($subtype eq 'stl-vector') {
            if ($os eq 'linux' or $os eq 'windows') {
                return ($arch == 64) ? 24 : 12;
            } else {
                print "sizeof stl-vector on $os\n";
            }
        } elsif ($subtype eq 'stl-bit-vector') {
            if ($os eq 'linux') {
                return ($arch == 64) ? 40 : 20;
            } elsif ($os eq 'windows') {
                return ($arch == 64) ? 32 : 16;
            } else {
                print "sizeof stl-bit-vector on $os\n";
            }
        } elsif ($subtype eq 'stl-deque') {
            if ($os eq 'linux') {
                return ($arch == 64) ? 80 : 40;
            } elsif ($os eq 'windows') {
                return ($arch == 64) ? 40 : 20;
            } else {
                print "sizeof stl-deque on $os\n";
            }
        } elsif ($subtype eq 'df-linked-list') {
            return 3 * $SIZEOF_PTR;
        } elsif ($subtype eq 'df-flagarray') {
            return 4 + $SIZEOF_PTR;
        } elsif ($subtype eq 'df-static-flagarray') {
            return $field->getAttribute('count');
        } elsif ($subtype eq 'df-array') {
            return 4 + $SIZEOF_PTR;   # XXX 4->2 ?
        } else {
            print "sizeof container $subtype\n";
        }

    } elsif ($meta eq 'primitive') {
        my $subtype = $field->getAttribute('ld:subtype');

        if ($subtype eq 'stl-string') {
            if ($os eq 'linux') {
                return ($arch == 64) ? 8 : 4;
            } elsif ($os eq 'windows') {
                return ($arch == 64) ? 32 : 24;
            } else {
                print "sizeof stl-string on $os\n";
            }
            print "sizeof stl-string\n";
        } elsif ($subtype eq 'stl-fstream') {
            if ($os eq 'linux') {
                return 284; # TODO: fix on x64
            } elsif ($os eq 'windows') {
                return ($arch == 64) ? 280 : 192;
            } else {
                print "sizeof stl-fstream on $os\n";
            }
            print "sizeof stl-fstream\n";
        } else {
            print "sizeof primitive $subtype\n";
        }

    } elsif ($meta eq 'bytes') {
        return $field->getAttribute('size');
    } else {
        print "sizeof $meta\n";
    }
}

sub sizeof_compound {
    my ($field) = @_;

    my $typename = $field->getAttribute('type-name');
    return $sizeof_cache{$typename} if $typename and $sizeof_cache{$typename};

    my $meta = $field->getAttribute('ld:meta');

    my $st = $field->getAttribute('ld:subtype') || '';
    if ($st eq 'bitfield' or $st eq 'enum')
    {
        my $base = $field->getAttribute('base-type') || 'uint32_t';
        if ($base eq 'long') {
            $sizeof_cache{$typename} = $SIZEOF_LONG if $typename;
            return $SIZEOF_LONG;
        }
        print "$st type $base\n" if $base !~ /int(\d+)_t/;
        $sizeof_cache{$typename} = $1/8 if $typename;
        return $1/8;
    }

    if ($field->getAttribute('is-union'))
    {
        my $sz = 0;
        for my $f ($field->findnodes('child::ld:field'))
        {
            my $fsz = sizeof($f);
            $sz = $fsz if $fsz > $sz;
        }
        return $sz;
    }

    my $parent = $field->getAttribute('inherits-from');
    my $off = 0;
    $off = $SIZEOF_PTR if ($meta eq 'class-type');
    $off = sizeof($global_types{$parent}) if ($parent);

    my $al = 1;
    $al = $SIZEOF_PTR if ($meta eq 'class-type');

    for my $f ($field->findnodes('child::ld:field'))
    {
        my $fa = get_field_align($f);
        $al = $fa if $fa > $al;
        $off = align_field($off, $fa);
        $off += sizeof($f);
    }

    # GCC: class a { vtable; char; } ; class b:a { char c2; } -> c2 has offset 5 (Windows MSVC: offset 8)
    $al = 1 if ($meta eq 'class-type' and $os eq 'linux');
    $off = align_field($off, $al);
    $sizeof_cache{$typename} = $off if $typename;

    return $off;
}


my $doc = XML::LibXML->new()->parse_file($input);
$global_types{$_->getAttribute('type-name')} = $_ foreach $doc->findnodes('/ld:data-definition/ld:global-type');

print get_sizeof($global_types{$target_class}) . "\n";

