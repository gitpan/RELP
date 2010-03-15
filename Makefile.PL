use 5.008008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'RELP',
    VERSION_FROM      => 'lib/RELP.pm', # finds $VERSION
    PREREQ_PM         => {
        'Class::Accessor' => 0.31,
        'Carp'            => 1,
        'IO::Socket'      => 1.24,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/RELP.pm', # retrieve abstract from module
       AUTHOR         => 'A. U. Thor <i.trunaev@localdomain>') : ()),
);
