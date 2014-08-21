#!/usr/bin/perl

# input is 1st argument or 'codegen/codegen.out.xml'
# 2nd arg is either 'linux' or 'windows' ; for osx use linux

use strict;
use warnings;

my $input = $ARGV[0] or die 'need path to codegen.out.xml';
my $target_class = 'unit';
my $os = $ARGV[1] || 'linux';

use XML::LibXML;

my %global_types;

our $compound_off;
our $compound_pointer;

sub get_sizeof {
    my ($type) = @_;
    my $meta = $type->getAttribute('ld:meta');
    local $compound_off = 0;
    $compound_off = 4 if ($meta eq 'class-type');
    my $sz = sizeof($type);
    # see comment is sub sizeof ; but gcc has sizeof(cls) aligned
    $sz = align_field($sz, 4) if $os eq 'linux' and $meta eq 'class-type';
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
    my $al = 4;
    my $meta = $field->getAttribute('ld:meta');

    if ($meta eq 'number') {
        $al = $field->getAttribute('ld:bits')/8;
        # linux aligns int64_t to 4, windows to 8
        # floats are 4 bytes so no pb
        $al = 4 if ($al > 4 and ($os eq 'linux' or $al != 8));
    } elsif ($meta eq 'global') {
        $al = get_global_align($field);
    } elsif ($meta eq 'compound') {
        $al = get_compound_align($field);
    } elsif ($meta eq 'static-array') {
        my $tg = $field->findnodes('child::ld:item')->[0];
        $al = get_field_align($tg);
    } elsif ($meta eq 'bytes') {
        $al = $field->getAttribute('alignment') || 1;
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
        return $field->getAttribute('ld:bits')/8;

    } elsif ($meta eq 'pointer') {
        return 4;

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
            if ($os eq 'linux') {
                return 12;
            } elsif ($os eq 'windows') {
                return 16;
            } else {
                print "sizeof stl-vector on $os\n";
            }
        } elsif ($subtype eq 'stl-bit-vector') {
            if ($os eq 'linux') {
                return 20;
            } elsif ($os eq 'windows') {
                return 20;
            } else {
                print "sizeof stl-bit-vector on $os\n";
            }
        } elsif ($subtype eq 'stl-deque') {
            if ($os eq 'linux') {
                return 40;
            } elsif ($os eq 'windows') {
                return 24;
            } else {
                print "sizeof stl-deque on $os\n";
            }
        } elsif ($subtype eq 'df-linked-list') {
            return 12;
        } elsif ($subtype eq 'df-flagarray') {
            return 8;
        } elsif ($subtype eq 'df-static-flagarray') {
            return $field->getAttribute('count');
        } elsif ($subtype eq 'df-array') {
            return 8;   # XXX 6 ?
        } else {
            print "sizeof container $subtype\n";
        }

    } elsif ($meta eq 'primitive') {
        my $subtype = $field->getAttribute('ld:subtype');

        if ($subtype eq 'stl-string') { if ($os eq 'linux') {
                return 4;
            } elsif ($os eq 'windows') {
                return 28;
            } else {
                print "sizeof stl-string on $os\n";
            }
            print "sizeof stl-string\n";
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
    $off = 4 if ($meta eq 'class-type');
    $off = sizeof($global_types{$parent}) if ($parent);

    my $al = 1;
    $al = 4 if ($meta eq 'class-type');

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

