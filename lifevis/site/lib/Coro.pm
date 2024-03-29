=head1 NAME

Coro - coroutine process abstraction

=head1 SYNOPSIS

  use Coro;
  
  async {
     # some asynchronous thread of execution
     print "2\n";
     cede; # yield back to main
     print "4\n";
  };
  print "1\n";
  cede; # yield to coroutine
  print "3\n";
  cede; # and again
  
  # use locking
  use Coro::Semaphore;
  my $lock = new Coro::Semaphore;
  my $locked;
  
  $lock->down;
  $locked = 1;
  $lock->up;

=head1 DESCRIPTION

This module collection manages coroutines. Coroutines are similar to
threads but don't (in general) run in parallel at the same time even
on SMP machines. The specific flavor of coroutine used in this module
also guarantees you that it will not switch between coroutines unless
necessary, at easily-identified points in your program, so locking and
parallel access are rarely an issue, making coroutine programming much
safer and easier than threads programming.

Unlike a normal perl program, however, coroutines allow you to have
multiple running interpreters that share data, which is especially useful
to code pseudo-parallel processes and for event-based programming, such as
multiple HTTP-GET requests running concurrently. See L<Coro::AnyEvent> to
learn more.

Coroutines are also useful because Perl has no support for threads (the so
called "threads" that perl offers are nothing more than the (bad) process
emulation coming from the Windows platform: On standard operating systems
they serve no purpose whatsoever, except by making your programs slow and
making them use a lot of memory. Best disable them when building perl, or
aks your software vendor/distributor to do it for you).

In this module, coroutines are defined as "callchain + lexical variables +
@_ + $_ + $@ + $/ + C stack), that is, a coroutine has its own callchain,
its own set of lexicals and its own set of perls most important global
variables (see L<Coro::State> for more configuration).

=cut

package Coro;

use strict qw(vars subs);
no warnings "uninitialized";

use Coro::State;

use base qw(Coro::State Exporter);

our $idle;    # idle handler
our $main;    # main coroutine
our $current; # current coroutine

our $VERSION = "5.0";

our @EXPORT = qw(async async_pool cede schedule terminate current unblock_sub);
our %EXPORT_TAGS = (
      prio => [qw(PRIO_MAX PRIO_HIGH PRIO_NORMAL PRIO_LOW PRIO_IDLE PRIO_MIN)],
);
our @EXPORT_OK = (@{$EXPORT_TAGS{prio}}, qw(nready));

=over 4

=item $Coro::main

This variable stores the coroutine object that represents the main
program. While you cna C<ready> it and do most other things you can do to
coroutines, it is mainly useful to compare again C<$Coro::current>, to see
whether you are running in the main program or not.

=cut

# $main is now being initialised by Coro::State

=item $Coro::current

The coroutine object representing the current coroutine (the last
coroutine that the Coro scheduler switched to). The initial value is
C<$Coro::main> (of course).

This variable is B<strictly> I<read-only>. You can take copies of the
value stored in it and use it as any other coroutine object, but you must
not otherwise modify the variable itself.

=cut

sub current() { $current } # [DEPRECATED]

=item $Coro::idle

This variable is mainly useful to integrate Coro into event loops. It is
usually better to rely on L<Coro::AnyEvent> or LC<Coro::EV>, as this is
pretty low-level functionality.

This variable stores a callback that is called whenever the scheduler
finds no ready coroutines to run. The default implementation prints
"FATAL: deadlock detected" and exits, because the program has no other way
to continue.

This hook is overwritten by modules such as C<Coro::Timer> and
C<Coro::AnyEvent> to wait on an external event that hopefully wake up a
coroutine so the scheduler can run it.

Note that the callback I<must not>, under any circumstances, block
the current coroutine. Normally, this is achieved by having an "idle
coroutine" that calls the event loop and then blocks again, and then
readying that coroutine in the idle handler.

See L<Coro::Event> or L<Coro::AnyEvent> for examples of using this
technique.

Please note that if your callback recursively invokes perl (e.g. for event
handlers), then it must be prepared to be called recursively itself.

=cut

$idle = sub {
   require Carp;
   Carp::croak ("FATAL: deadlock detected");
};

# this coroutine is necessary because a coroutine
# cannot destroy itself.
our @destroy;
our $manager;

$manager = new Coro sub {
   while () {
      Coro::_cancel shift @destroy
         while @destroy;

      &schedule;
   }
};
$manager->{desc} = "[coro manager]";
$manager->prio (PRIO_MAX);

=back

=head2 SIMPLE COROUTINE CREATION

=over 4

=item async { ... } [@args...]

Create a new coroutine and return it's coroutine object (usually
unused). The coroutine will be put into the ready queue, so
it will start running automatically on the next scheduler run.

The first argument is a codeblock/closure that should be executed in the
coroutine. When it returns argument returns the coroutine is automatically
terminated.

The remaining arguments are passed as arguments to the closure.

See the C<Coro::State::new> constructor for info about the coroutine
environment in which coroutines are executed.

Calling C<exit> in a coroutine will do the same as calling exit outside
the coroutine. Likewise, when the coroutine dies, the program will exit,
just as it would in the main program.

If you do not want that, you can provide a default C<die> handler, or
simply avoid dieing (by use of C<eval>).

Example: Create a new coroutine that just prints its arguments.

   async {
      print "@_\n";
   } 1,2,3,4;

=cut

sub async(&@) {
   my $coro = new Coro @_;
   $coro->ready;
   $coro
}

=item async_pool { ... } [@args...]

Similar to C<async>, but uses a coroutine pool, so you should not call
terminate or join on it (although you are allowed to), and you get a
coroutine that might have executed other code already (which can be good
or bad :).

On the plus side, this function is about twice as fast as creating (and
destroying) a completely new coroutine, so if you need a lot of generic
coroutines in quick successsion, use C<async_pool>, not C<async>.

The code block is executed in an C<eval> context and a warning will be
issued in case of an exception instead of terminating the program, as
C<async> does. As the coroutine is being reused, stuff like C<on_destroy>
will not work in the expected way, unless you call terminate or cancel,
which somehow defeats the purpose of pooling (but is fine in the
exceptional case).

The priority will be reset to C<0> after each run, tracing will be
disabled, the description will be reset and the default output filehandle
gets restored, so you can change all these. Otherwise the coroutine will
be re-used "as-is": most notably if you change other per-coroutine global
stuff such as C<$/> you I<must needs> revert that change, which is most
simply done by using local as in: C<< local $/ >>.

The idle pool size is limited to C<8> idle coroutines (this can be
adjusted by changing $Coro::POOL_SIZE), but there can be as many non-idle
coros as required.

If you are concerned about pooled coroutines growing a lot because a
single C<async_pool> used a lot of stackspace you can e.g. C<async_pool
{ terminate }> once per second or so to slowly replenish the pool. In
addition to that, when the stacks used by a handler grows larger than 16kb
(adjustable via $Coro::POOL_RSS) it will also be destroyed.

=cut

our $POOL_SIZE = 8;
our $POOL_RSS  = 16 * 1024;
our @async_pool;

sub pool_handler {
   while () {
      eval {
         &{&_pool_handler} while 1;
      };

      warn $@ if $@;
   }
}

=back

=head2 STATIC METHODS

Static methods are actually functions that operate on the current coroutine.

=over 4

=item schedule

Calls the scheduler. The scheduler will find the next coroutine that is
to be run from the ready queue and switches to it. The next coroutine
to be run is simply the one with the highest priority that is longest
in its ready queue. If there is no coroutine ready, it will clal the
C<$Coro::idle> hook.

Please note that the current coroutine will I<not> be put into the ready
queue, so calling this function usually means you will never be called
again unless something else (e.g. an event handler) calls C<< ->ready >>,
thus waking you up.

This makes C<schedule> I<the> generic method to use to block the current
coroutine and wait for events: first you remember the current coroutine in
a variable, then arrange for some callback of yours to call C<< ->ready
>> on that once some event happens, and last you call C<schedule> to put
yourself to sleep. Note that a lot of things can wake your coroutine up,
so you need to check whether the event indeed happened, e.g. by storing the
status in a variable.

See B<HOW TO WAIT FOR A CALLBACK>, below, for some ways to wait for callbacks.

=item cede

"Cede" to other coroutines. This function puts the current coroutine into
the ready queue and calls C<schedule>, which has the effect of giving
up the current "timeslice" to other coroutines of the same or higher
priority. Once your coroutine gets its turn again it will automatically be
resumed.

This function is often called C<yield> in other languages.

=item Coro::cede_notself

Works like cede, but is not exported by default and will cede to I<any>
coroutine, regardless of priority. This is useful sometimes to ensure
progress is made.

=item terminate [arg...]

Terminates the current coroutine with the given status values (see L<cancel>).

=item killall

Kills/terminates/cancels all coroutines except the currently running
one. This is useful after a fork, either in the child or the parent, as
usually only one of them should inherit the running coroutines.

Note that while this will try to free some of the main programs resources,
you cannot free all of them, so if a coroutine that is not the main
program calls this function, there will be some one-time resource leak.

=cut

sub killall {
   for (Coro::State::list) {
      $_->cancel
         if $_ != $current && UNIVERSAL::isa $_, "Coro";
   }
}

=back

=head2 COROUTINE METHODS

These are the methods you can call on coroutine objects (or to create
them).

=over 4

=item new Coro \&sub [, @args...]

Create a new coroutine and return it. When the sub returns, the coroutine
automatically terminates as if C<terminate> with the returned values were
called. To make the coroutine run you must first put it into the ready
queue by calling the ready method.

See C<async> and C<Coro::State::new> for additional info about the
coroutine environment.

=cut

sub _terminate {
   terminate &{+shift};
}

=item $success = $coroutine->ready

Put the given coroutine into the end of its ready queue (there is one
queue for each priority) and return true. If the coroutine is already in
the ready queue, do nothing and return false.

This ensures that the scheduler will resume this coroutine automatically
once all the coroutines of higher priority and all coroutines of the same
priority that were put into the ready queue earlier have been resumed.

=item $is_ready = $coroutine->is_ready

Return whether the coroutine is currently the ready queue or not,

=item $coroutine->cancel (arg...)

Terminates the given coroutine and makes it return the given arguments as
status (default: the empty list). Never returns if the coroutine is the
current coroutine.

=cut

sub cancel {
   my $self = shift;

   if ($current == $self) {
      terminate @_;
   } else {
      $self->{_status} = [@_];
      $self->_cancel;
   }
}

=item $coroutine->schedule_to

Puts the current coroutine to sleep (like C<Coro::schedule>), but instead
of continuing with the next coro from the ready queue, always switch to
the given coroutine object (regardless of priority etc.). The readyness
state of that coroutine isn't changed.

This is an advanced method for special cases - I'd love to hear about any
uses for this one.

=item $coroutine->cede_to

Like C<schedule_to>, but puts the current coroutine into the ready
queue. This has the effect of temporarily switching to the given
coroutine, and continuing some time later.

This is an advanced method for special cases - I'd love to hear about any
uses for this one.

=item $coroutine->throw ([$scalar])

If C<$throw> is specified and defined, it will be thrown as an exception
inside the coroutine at the next convenient point in time. Otherwise
clears the exception object.

Coro will check for the exception each time a schedule-like-function
returns, i.e. after each C<schedule>, C<cede>, C<< Coro::Semaphore->down
>>, C<< Coro::Handle->readable >> and so on. Most of these functions
detect this case and return early in case an exception is pending.

The exception object will be thrown "as is" with the specified scalar in
C<$@>, i.e. if it is a string, no line number or newline will be appended
(unlike with C<die>).

This can be used as a softer means than C<cancel> to ask a coroutine to
end itself, although there is no guarantee that the exception will lead to
termination, and if the exception isn't caught it might well end the whole
program.

You might also think of C<throw> as being the moral equivalent of
C<kill>ing a coroutine with a signal (in this case, a scalar).

=item $coroutine->join

Wait until the coroutine terminates and return any values given to the
C<terminate> or C<cancel> functions. C<join> can be called concurrently
from multiple coroutines, and all will be resumed and given the status
return once the C<$coroutine> terminates.

=cut

sub join {
   my $self = shift;

   unless ($self->{_status}) {
      my $current = $current;

      push @{$self->{_on_destroy}}, sub {
         $current->ready;
         undef $current;
      };

      &schedule while $current;
   }

   wantarray ? @{$self->{_status}} : $self->{_status}[0];
}

=item $coroutine->on_destroy (\&cb)

Registers a callback that is called when this coroutine gets destroyed,
but before it is joined. The callback gets passed the terminate arguments,
if any, and I<must not> die, under any circumstances.

=cut

sub on_destroy {
   my ($self, $cb) = @_;

   push @{ $self->{_on_destroy} }, $cb;
}

=item $oldprio = $coroutine->prio ($newprio)

Sets (or gets, if the argument is missing) the priority of the
coroutine. Higher priority coroutines get run before lower priority
coroutines. Priorities are small signed integers (currently -4 .. +3),
that you can refer to using PRIO_xxx constants (use the import tag :prio
to get then):

   PRIO_MAX > PRIO_HIGH > PRIO_NORMAL > PRIO_LOW > PRIO_IDLE > PRIO_MIN
       3    >     1     >      0      >    -1    >    -3     >    -4

   # set priority to HIGH
   current->prio(PRIO_HIGH);

The idle coroutine ($Coro::idle) always has a lower priority than any
existing coroutine.

Changing the priority of the current coroutine will take effect immediately,
but changing the priority of coroutines in the ready queue (but not
running) will only take effect after the next schedule (of that
coroutine). This is a bug that will be fixed in some future version.

=item $newprio = $coroutine->nice ($change)

Similar to C<prio>, but subtract the given value from the priority (i.e.
higher values mean lower priority, just as in unix).

=item $olddesc = $coroutine->desc ($newdesc)

Sets (or gets in case the argument is missing) the description for this
coroutine. This is just a free-form string you can associate with a
coroutine.

This method simply sets the C<< $coroutine->{desc} >> member to the given
string. You can modify this member directly if you wish.

=cut

sub desc {
   my $old = $_[0]{desc};
   $_[0]{desc} = $_[1] if @_ > 1;
   $old;
}

=back

=head2 GLOBAL FUNCTIONS

=over 4

=item Coro::nready

Returns the number of coroutines that are currently in the ready state,
i.e. that can be switched to by calling C<schedule> directory or
indirectly. The value C<0> means that the only runnable coroutine is the
currently running one, so C<cede> would have no effect, and C<schedule>
would cause a deadlock unless there is an idle handler that wakes up some
coroutines.

=item my $guard = Coro::guard { ... }

This creates and returns a guard object. Nothing happens until the object
gets destroyed, in which case the codeblock given as argument will be
executed. This is useful to free locks or other resources in case of a
runtime error or when the coroutine gets canceled, as in both cases the
guard block will be executed. The guard object supports only one method,
C<< ->cancel >>, which will keep the codeblock from being executed.

Example: set some flag and clear it again when the coroutine gets canceled
or the function returns:

   sub do_something {
      my $guard = Coro::guard { $busy = 0 };
      $busy = 1;

      # do something that requires $busy to be true
   }

=cut

sub guard(&) {
   bless \(my $cb = $_[0]), "Coro::guard"
}

sub Coro::guard::cancel {
   ${$_[0]} = sub { };
}

sub Coro::guard::DESTROY {
   ${$_[0]}->();
}


=item unblock_sub { ... }

This utility function takes a BLOCK or code reference and "unblocks" it,
returning a new coderef. Unblocking means that calling the new coderef
will return immediately without blocking, returning nothing, while the
original code ref will be called (with parameters) from within another
coroutine.

The reason this function exists is that many event libraries (such as the
venerable L<Event|Event> module) are not coroutine-safe (a weaker form
of thread-safety). This means you must not block within event callbacks,
otherwise you might suffer from crashes or worse. The only event library
currently known that is safe to use without C<unblock_sub> is L<EV>.

This function allows your callbacks to block by executing them in another
coroutine where it is safe to block. One example where blocking is handy
is when you use the L<Coro::AIO|Coro::AIO> functions to save results to
disk, for example.

In short: simply use C<unblock_sub { ... }> instead of C<sub { ... }> when
creating event callbacks that want to block.

If your handler does not plan to block (e.g. simply sends a message to
another coroutine, or puts some other coroutine into the ready queue),
there is no reason to use C<unblock_sub>.

Note that you also need to use C<unblock_sub> for any other callbacks that
are indirectly executed by any C-based event loop. For example, when you
use a module that uses L<AnyEvent> (and you use L<Coro::AnyEvent>) and it
provides callbacks that are the result of some event callback, then you
must not block either, or use C<unblock_sub>.

=cut

our @unblock_queue;

# we create a special coro because we want to cede,
# to reduce pressure on the coro pool (because most callbacks
# return immediately and can be reused) and because we cannot cede
# inside an event callback.
our $unblock_scheduler = new Coro sub {
   while () {
      while (my $cb = pop @unblock_queue) {
         &async_pool (@$cb);

         # for short-lived callbacks, this reduces pressure on the coro pool
         # as the chance is very high that the async_poll coro will be back
         # in the idle state when cede returns
         cede;
      }
      schedule; # sleep well
   }
};
$unblock_scheduler->{desc} = "[unblock_sub scheduler]";

sub unblock_sub(&) {
   my $cb = shift;

   sub {
      unshift @unblock_queue, [$cb, @_];
      $unblock_scheduler->ready;
   }
}

=item $cb = Coro::rouse_cb

Create and return a "rouse callback". That's a code reference that, when
called, will save its arguments and notify the owner coroutine of the
callback.

See the next function.

=item @args = Coro::rouse_wait [$cb]

Wait for the specified rouse callback (or the last one tht was created in
this coroutine).

As soon as the callback is invoked (or when the calback was invoked before
C<rouse_wait>), it will return a copy of the arguments originally passed
to the rouse callback.

See the section B<HOW TO WAIT FOR A CALLBACK> for an actual usage example.

=back

=cut

1;

=head1 HOW TO WAIT FOR A CALLBACK

It is very common for a coroutine to wait for some callback to be
called. This occurs naturally when you use coroutines in an otherwise
event-based program, or when you use event-based libraries.

These typically register a callback for some event, and call that callback
when the event occured.  In a coroutine, however, you typically want to
just wait for the event, simplyifying things.

For example C<< AnyEvent->child >> registers a callback to be called when
a specific child has exited:

   my $child_watcher = AnyEvent->child (pid => $pid, cb => sub { ... });

But from withina coroutine, you often just want to write this:

   my $status = wait_for_child $pid;

Coro offers two functions specifically designed to make this easy,
C<Coro::rouse_cb> and C<Coro::rouse_wait>.

The first function, C<rouse_cb>, generates and returns a callback that,
when invoked, will save it's arguments and notify the coroutine that
created the callback.

The second function, C<rouse_wait>, waits for the callback to be called
(by calling C<schedule> to go to sleep) and returns the arguments
originally passed to the callback.

Using these functions, it becomes easy to write the C<wait_for_child>
function mentioned above:

   sub wait_for_child($) {
      my ($pid) = @_;

      my $watcher = AnyEvent->child (pid => $pid, cb => Coro::rouse_cb);

      my ($rpid, $rstatus) = Coro::rouse_wait;
      $rstatus
   }

In the case where C<rouse_cb> and C<rouse_wait> are not flexible enough,
you can roll your own, using C<schedule>:

   sub wait_for_child($) {
      my ($pid) = @_;

      # store the current coroutine in $current,
      # and provide result variables for the closure passed to ->child
      my $current = $Coro::current;
      my ($done, $rstatus);

      # pass a closure to ->child
      my $watcher = AnyEvent->child (pid => $pid, cb => sub {
         $rstatus = $_[1]; # remember rstatus
         $done = 1; # mark $rstatus as valud
      });

      # wait until the closure has been called
      schedule while !$done;

      $rstatus
   }


=head1 BUGS/LIMITATIONS

=over 4

=item fork with pthread backend

When Coro is compiled using the pthread backend (which isn't recommended
but required on many BSDs as their libcs are completely broken), then
coroutines will not survive a fork. There is no known workaround except to
fix your libc and use a saner backend.

=item perl process emulation ("threads")

This module is not perl-pseudo-thread-safe. You should only ever use this
module from the same thread (this requirement might be removed in the
future to allow per-thread schedulers, but Coro::State does not yet allow
this). I recommend disabling thread support and using processes, as having
the windows process emulation enabled under unix roughly halves perl
performance, even when not used.

=item coroutine switching not signal safe

You must not switch to another coroutine from within a signal handler
(only relevant with %SIG - most event libraries provide safe signals).

That means you I<MUST NOT> call any function that might "block" the
current coroutine - C<cede>, C<schedule> C<< Coro::Semaphore->down >> or
anything that calls those. Everything else, including calling C<ready>,
works.

=back


=head1 SEE ALSO

Event-Loop integration: L<Coro::AnyEvent>, L<Coro::EV>, L<Coro::Event>.

Debugging: L<Coro::Debug>.

Support/Utility: L<Coro::Specific>, L<Coro::Util>.

Locking/IPC: L<Coro::Signal>, L<Coro::Channel>, L<Coro::Semaphore>, L<Coro::SemaphoreSet>, L<Coro::RWLock>.

IO/Timers: L<Coro::Timer>, L<Coro::Handle>, L<Coro::Socket>, L<Coro::AIO>.

Compatibility: L<Coro::LWP>, L<Coro::BDB>, L<Coro::Storable>, L<Coro::Select>.

XS API: L<Coro::MakeMaker>.

Low level Configuration, Coroutine Environment: L<Coro::State>.

=head1 AUTHOR

 Marc Lehmann <schmorp@schmorp.de>
 http://home.schmorp.de/

=cut

