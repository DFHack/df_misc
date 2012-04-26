#!/usr/bin/perl

use strict;
use warnings;

use XML::LibXML;

our @lines;

sub indent(&) {
    my ($sub) = @_;
    my @lines2;
    {
        local @lines;
        $sub->();
        @lines2 = map { "    " . $_ } @lines;
    }
    push @lines, @lines2
}

my %global_type_renderer = (
    'enum-type' => \&render_global_enum,
    'struct-type' => \&render_global_class,
    'class-type' => \&render_global_class,
    'bitfield-type' => \&render_global_bitfield,
);

my %item_renderer = (
    'global' => \&render_item_global,
    'number' => \&render_item_number,
    'container' => \&render_item_container,
    'compound' => \&render_item_compound,
    'pointer' => \&render_item_pointer,
    'static-array' => \&render_item_staticarray,
    'primitive' => \&render_item_primitive,
    'bytes' => \&render_item_bytes,
);


sub render_global_enum {
    my ($name, $type) = @_;

    push @lines, "enum $name {";
    indent {
        render_enum_fields($type);
    };
    push @lines, "};\n";
}
sub render_enum_fields {
    my ($type) = @_;

    my $value = -1;
    for my $item ($type->findnodes('child::enum-item')) {
        $value += 1;
        my $newvalue = $item->getAttribute('value') || $value;
        my $elemname = $item->getAttribute('name'); # || "unk_$value";

        if ($elemname) {
            if ($value == $newvalue) {
                push @lines, "$elemname,";
            } else {
                push @lines, "$elemname = $newvalue,";
            }
        }

        $value = $newvalue;
    }

    chop $lines[$#lines] if (@lines);      # remove last coma
}


sub render_global_bitfield {
    my ($name, $type) = @_;

    push @lines, "struct $name {";
    indent {
        render_bitfield_fields($type);
    };
    push @lines, "};\n";
}
sub render_bitfield_fields {
    my ($type) = @_;

    my $shift = 0;
    for my $field ($type->findnodes('child::ld:field')) {
        my $count = $field->getAttribute('count') || 1;
        my $name = $field->getAttribute('name');
        $name = $field->getAttribute('ld:anon-name') || '' if (!$name);
        push @lines, "int $name:$count;";
        $shift += $count;
    }
}


my %global_types;
my %seen_class;
sub render_global_class {
    my ($name, $type) = @_;

    # ensure pre-definition of ancestors
    my $parent = $type->getAttribute('inherits-from');
    if ($parent) {
        render_global_class($parent, $global_types{$parent}) if (!$seen_class{$parent});
        my $oparent = $global_types{$parent}->getAttribute('original-name');
        $parent = $oparent if $oparent;
    }

    return if $seen_class{$name};
    $seen_class{$name}++;

    my $rtti_name = $type->getAttribute('original-name') ||
                    $type->getAttribute('type-name') ||
                    $name;

    my $has_rtti = $parent;
    if (!$parent and $type->getAttribute('ld:meta') eq 'class-type') {
        for my $anytypename (keys %global_types) {
            my $anytype = $global_types{$anytypename};
            if ($anytype->getAttribute('ld:meta') eq 'class-type') {
                my $anyparent = $anytype->getAttribute('inherits-from');
                $has_rtti = 1 if ($anyparent and $anyparent eq $name);
            }
        }
    }

    push @lines, "struct $rtti_name {";
    indent {
        if ($parent) {
            push @lines, "struct $parent super;";
        } elsif ($has_rtti) {
            push @lines, "void **vtable;";
        }
        render_struct_fields($type);
    };
    push @lines, "};\n";
}
sub render_struct_fields {
    my ($type) = @_;

    for my $field ($type->findnodes('child::ld:field')) {
        my $name = $field->getAttribute('name');
        $name = $field->getAttribute('ld:anon-name') if (!$name);
        if (!$name and $field->getAttribute('ld:anon-compound')) {
            render_struct_fields($field);
        }
        #next if (!$name);
        render_item($field, $name)
    }
}

sub render_global_objects {
    my (@objects) = @_;

    for my $obj (@objects) {
        my $oname = $obj->getAttribute('name');
        my $item = $obj->findnodes('child::ld:item')->[0];
        render_item($item, $oname);
    }
}


sub render_item {
    my ($item, $name) = @_;
    if (!$item) {
        push @lines, "// noitem $name";
        return;
    }

    my $meta = $item->getAttribute('ld:meta');

    my $renderer = $item_renderer{$meta};
    if ($renderer) {
        $renderer->($item, $name);
    } else {
        print "no render item $meta\n";
    }
}

sub render_item_global {
    my ($item, $name) = @_;

    my $typename = $item->getAttribute('type-name');
    my $subtype = $item->getAttribute('ld:subtype');

    if ($subtype and $subtype eq 'enum') {
        render_item_number($item, $name);
    } else {
        push @lines, "struct $typename $name;";
    }
}

sub render_item_number {
    my ($item, $name) = @_;

    my $subtype = $item->getAttribute('ld:subtype');
    $subtype = $item->getAttribute('base-type') if (!$subtype or $subtype eq 'enum' or $subtype eq 'bitfield');
    $subtype = 'int32_t' if (!$subtype);
    $subtype = 'int8_t' if ($subtype eq 'bool');
    push @lines, "$subtype $name;";
}

sub render_item_compound {
    my ($item, $name) = @_;

    my $subtype = $item->getAttribute('ld:subtype');
    if (!$subtype || $subtype eq 'bitfield') {
        push @lines, "struct {";
        indent {
            if (!$subtype) {
                render_struct_fields($item);
            } else {
                render_bitfield_fields($item);
            }
        };
        $name ||= '';
        push @lines, "} $name;"
    } elsif ($subtype eq 'enum') {
        push @lines, "enum {";
        indent {
            render_enum_fields($item);
        };
        push @lines, "} $name;";
    } else {
        print "no render compound $subtype\n";
    }
}

sub render_item_container {
    my ($item, $name) = @_;

    my $subtype = $item->getAttribute('ld:subtype');
    $subtype = join('_', split('-', $subtype));
    #my $tg = $item->findnodes('child::ld:item')->[0];
    push @lines, "struct $subtype $name;";
}

sub render_item_pointer {
    my ($item, $name) = @_;

    my $tg = $item->findnodes('child::ld:item')->[0];
    render_item($tg, "*$name");
}

sub render_item_staticarray {
    my ($item, $name) = @_;

    my $count = $item->getAttribute('count');
    my $tg = $item->findnodes('child::ld:item')->[0];
    render_item($tg, "${name}[$count]");
}

sub render_item_primitive {
    my ($item, $name) = @_;

    my $subtype = $item->getAttribute('ld:subtype');
    if ($subtype eq 'stl-string') {
        push @lines, "struct stl_string $name;";
    } else {
        print "no render primitive $subtype\n";
    }
}

sub render_item_bytes {
    my ($item, $name) = @_;

    my $subtype = $item->getAttribute('ld:subtype');
    if ($subtype eq 'padding') {
        my $size = $item->getAttribute('size');
        push @lines, "char ${name}[$size];";
    } elsif ($subtype eq 'static-string') {
        my $size = $item->getAttribute('size');
        push @lines, "char ${name}[$size];";
    } else {
        print "no render bytes $subtype\n";
    }
}

my $input = $ARGV[0] || 'library/include/df/codegen.out.xml';
my $output = 'codegen.h';

my $doc = XML::LibXML->new()->parse_file($input);
$global_types{$_->getAttribute('type-name')} = $_ foreach $doc->findnodes('/ld:data-definition/ld:global-type');

for my $name (sort { $a cmp $b } keys %global_types) {
    my $type = $global_types{$name};
    my $meta = $type->getAttribute('ld:meta');
    my $renderer = $global_type_renderer{$meta};
    if ($renderer) {
        $renderer->($name, $type);
    } else {
        print "no render global type $meta\n";
    }
}

render_global_objects($doc->findnodes('/ld:data-definition/ld:global-object'));

my $hdr = <<EOS;
typedef char      int8_t;
typedef short     int16_t;
typedef int       int32_t;
typedef long long int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

#if 1

// Windows STL
struct std_string {
    union {
        char buf[16];
        char *ptr;
    };
    int32_t len;
    int32_t capa;
    int32_t pad;
};

#define std_vector(type) struct { type *ptr; type *endptr; type *endalloc; int32_t pad; }

#else

// Linux Glibc STL
struct std_string {
    char *ptr;
};

#define std_vector(type) struct { type *ptr; type *endptr; type *endalloc; }

#endif

typedef struct std_string std_string;

EOS

open FH, ">$output";
print FH $hdr;
print FH "$_\n" for @lines;
close FH;
