<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Sculpt\Application;
	use Quellabs\Sculpt\ServiceProvider;
	
	class CanvasProvider extends ServiceProvider {
		
		public function register(Application $application): void {
			// Register the commands into the Sculpt application
			$this->registerCommands($application, [
				CreateControllerCommand::class,
				ListRoutesCommand::class,
				MatchRoutesCommand::class,
				RoutesCacheClearCommand::class,
				ScheduleRunCommand::class,
				SchedulerListCommand::class,
				CacheInitCommand::class,
				JwtInitCommand::class,
			]);
		}
	}