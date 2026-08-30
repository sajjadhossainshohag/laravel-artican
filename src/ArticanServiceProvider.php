<?php

namespace SajjadHossain\Artican;

use Illuminate\Support\ServiceProvider;
use SajjadHossain\Artican\Checks\Blade\MissingNamedRoutesCheck;
use SajjadHossain\Artican\Checks\Cache\SessionDriverMismatchCheck;
use SajjadHossain\Artican\Checks\Components\{
    AnonymousComponentCheck,
    ComponentClassCheck,
    ComponentNamespaceCheck,
};
use SajjadHossain\Artican\Checks\Config\{
    AbortIfWrongHttpCodeCheck,
    EarlyConfigAccessCheck,
    NonExistentConfigFileCheck,
    NonExistentConfigKeyCheck,
};
use SajjadHossain\Artican\Checks\Container\{
    InterfaceBoundToDeletedConcreteCheck,
    SingletonAfterFirstResolveCheck,
};
use SajjadHossain\Artican\Checks\Debug\DebugStatementLeftInCheck;
use SajjadHossain\Artican\Checks\Eloquent\{
    AccessorMutatorStyleConflictCheck,
    GetThenCountCheck,
    MissingGuardedOrFillableCheck,
    ValueVsFirstOnNullCheck,
    WithCountOnUndefinedRelationshipCheck,
};
use SajjadHossain\Artican\Checks\Env\{
    AppKeyCheck,
    EnvExampleMismatchCheck,
    MissingEnvKeysCheck,
};
use SajjadHossain\Artican\Checks\Events\{
    ListenerMissingHandleMethodCheck,
    MissingListenerClassCheck,
};
use SajjadHossain\Artican\Checks\Gates\MissingPolicyClassCheck;
use SajjadHossain\Artican\Checks\Jobs\{
    BusChainCheck,
    FailedJobTableMissingCheck,
    JobDependencyResolutionCheck,
    JobHasHandleMethodCheck,
    JobTriesZeroCheck,
    MissingJobClassCheck,
};
use SajjadHossain\Artican\Checks\Livewire\MissingLivewireComponentCheck;
use SajjadHossain\Artican\Checks\Mail\{
    MailableMissingViewCheck,
    MailableVariableMismatchCheck,
};
use SajjadHossain\Artican\Checks\Middleware\{
    TerminateMethodThrowsCheck,
    UnregisteredMiddlewareCheck,
};
use SajjadHossain\Artican\Checks\Routes\{
    DuplicateRouteNamesCheck,
    DuplicateUrisCheck,
    InvalidMiddlewareCheck,
    MissingControllerCheck,
    MissingControllerMethodCheck,
    RouteClosureBreaksCacheCheck,
};
use SajjadHossain\Artican\Checks\Schedule\{
    DeletedScheduledCommandCheck,
    OverlappingJobsWithoutLockCheck,
    ScheduledCommandNotExistsCheck,
};
use SajjadHossain\Artican\Checks\Schema\{
    ColumnMismatchCheck,
    InvalidCastsCheck,
};
use SajjadHossain\Artican\Checks\Security\RequestAllInCreateCheck;
use SajjadHossain\Artican\Checks\Storage\{
    MissingStorageSymlinkCheck,
    S3UrlWithoutConfigCheck,
    StoreAsPathTraversalCheck,
    UndefinedDiskCheck,
};
use SajjadHossain\Artican\Checks\Validation\{
    AuthorizeAlwaysFalseCheck,
    NonExistentRuleClassCheck,
};
use SajjadHossain\Artican\Checks\Views\{
    MissingComponentCheck,
    MissingExtendsCheck,
    MissingIncludeCheck,
    StackPushMismatchCheck,
};
use SajjadHossain\Artican\Commands\CacheClearCommand;
use SajjadHossain\Artican\Commands\ScanCommand;
use SajjadHossain\Artican\Commands\WorkerCommand;

class ArticanServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        if ($this->app->runningInConsole()) {
            $this->app->singleton(CheckRegistry::class);
            $this->app->singleton(ScanResultCache::class);
        }

        $this->mergeConfigFrom(__DIR__ . '/../config/artican.php', 'artican');
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/artican.php' => config_path('artican.php'),
        ], 'artican-config');

        if ($this->app->runningInConsole()) {
            $this->app->make(CheckRegistry::class)->registerMany([
                // Eloquent
                WithCountOnUndefinedRelationshipCheck::class,
                ValueVsFirstOnNullCheck::class,
                MissingGuardedOrFillableCheck::class,
                AccessorMutatorStyleConflictCheck::class,
                GetThenCountCheck::class,

                // Container
                InterfaceBoundToDeletedConcreteCheck::class,
                SingletonAfterFirstResolveCheck::class,

                // Env
                AppKeyCheck::class,
                EnvExampleMismatchCheck::class,
                MissingEnvKeysCheck::class,

                // Events
                MissingListenerClassCheck::class,
                ListenerMissingHandleMethodCheck::class,

                // Mail
                MailableMissingViewCheck::class,
                MailableVariableMismatchCheck::class,

                // Middleware
                UnregisteredMiddlewareCheck::class,
                TerminateMethodThrowsCheck::class,

                // Validation
                AuthorizeAlwaysFalseCheck::class,
                NonExistentRuleClassCheck::class,

                // Storage
                S3UrlWithoutConfigCheck::class,
                UndefinedDiskCheck::class,
                StoreAsPathTraversalCheck::class,
                MissingStorageSymlinkCheck::class,

                // Cache
                SessionDriverMismatchCheck::class,

                // Schedule
                ScheduledCommandNotExistsCheck::class,
                DeletedScheduledCommandCheck::class,
                OverlappingJobsWithoutLockCheck::class,

                // Gates
                MissingPolicyClassCheck::class,

                // Livewire
                MissingLivewireComponentCheck::class,

                // Queue / Jobs
                FailedJobTableMissingCheck::class,
                JobTriesZeroCheck::class,
                BusChainCheck::class,
                JobDependencyResolutionCheck::class,
                JobHasHandleMethodCheck::class,
                MissingJobClassCheck::class,

                // Config
                EarlyConfigAccessCheck::class,
                AbortIfWrongHttpCodeCheck::class,
                NonExistentConfigFileCheck::class,
                NonExistentConfigKeyCheck::class,

                // Blade
                MissingNamedRoutesCheck::class,

                // Components
                AnonymousComponentCheck::class,
                ComponentClassCheck::class,
                ComponentNamespaceCheck::class,

                // Routes
                DuplicateRouteNamesCheck::class,
                DuplicateUrisCheck::class,
                InvalidMiddlewareCheck::class,
                MissingControllerCheck::class,
                MissingControllerMethodCheck::class,
                RouteClosureBreaksCacheCheck::class,

                // Schema
                ColumnMismatchCheck::class,
                InvalidCastsCheck::class,

                // Views
                MissingComponentCheck::class,
                MissingExtendsCheck::class,
                MissingIncludeCheck::class,
                StackPushMismatchCheck::class,

                // Security
                RequestAllInCreateCheck::class,

                // Debug
                DebugStatementLeftInCheck::class,
            ]);

            $this->commands([
                ScanCommand::class,
                CacheClearCommand::class,
                WorkerCommand::class,
            ]);
        }
    }
}
