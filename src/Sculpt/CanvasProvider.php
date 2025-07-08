<?php
	
	namespace Quellabs\Canvas\Sculpt;
	
	use Quellabs\Sculpt\Application;
	use Quellabs\Sculpt\ServiceProvider;
	
	class CanvasProvider extends ServiceProvider {
		
		public function register(Application $application): void {
			// Register the commands into the Sculpt application
			$this->registerCommands($application, [
				ListRoutesCommand::class,
				MatchRoutesCommand::class,
				RoutesCacheClearCommand::class,
				PublishCommand::class,
				SchedulerRunCommand::class,
				SchedulerListCommand::class
			]);
		}
	}