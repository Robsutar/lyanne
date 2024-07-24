use std::{sync::Arc, time::Instant};

use bevy::{
    prelude::*,
    sprite::{MaterialMesh2dBundle, Mesh2dHandle},
};
use bevy_ping_pong::*;
use lyanne::{
    packets::ClientPacketResource,
    transport::client::{Client, ClientTickResult},
};
use rand::{thread_rng, Rng};

pub struct Ball {
    pub entity: Entity,
}

impl Ball {
    fn default_of(
        config: &GameConfig,
        commands: &mut Commands,
        meshes: &mut ResMut<Assets<Mesh>>,
        materials: &mut ResMut<Assets<ColorMaterial>>,
    ) -> Self {
        let x = (config.arena.min.x + config.arena.max.x) / 2.0;
        let y = (config.arena.min.y + config.arena.max.y) / 2.0;
        Self {
            entity: commands
                .spawn(MaterialMesh2dBundle {
                    mesh: Mesh2dHandle(meshes.add(Circle::new(config.ball_radius))),
                    material: materials.add(random_color()),
                    transform: Transform::from_xyz(x, y, 0.0),
                    ..default()
                })
                .id(),
        }
    }
}

pub struct Player {
    pub entity: Entity,
    pub name: String,
    pub side: PlayerSide,
    pub points: usize,
}

impl Player {
    fn default_of(
        config: &GameConfig,
        name: String,
        side: PlayerSide,
        commands: &mut Commands,
        meshes: &mut ResMut<Assets<Mesh>>,
        materials: &mut ResMut<Assets<ColorMaterial>>,
    ) -> Self {
        let x = {
            match side {
                PlayerSide::Left => config.arena.min.x,
                PlayerSide::Right => config.arena.max.x,
            }
        };
        let y = (config.arena.min.y + config.arena.max.y) / 2.0;

        Self {
            entity: commands
                .spawn(MaterialMesh2dBundle {
                    mesh: Mesh2dHandle(meshes.add(Rectangle::new(
                        config.player_bar_size.x,
                        config.player_bar_size.y,
                    ))),
                    material: materials.add(Color::srgb(0.0, 1.0, 0.0)),
                    transform: Transform::from_xyz(x, y, 0.0),
                    ..default()
                })
                .id(),
            name,
            side,
            points: 0,
        }
    }
}

#[derive(Resource)]
struct ServerPacketSchedule {
    game_entity: Entity,
}

#[derive(Component)]
pub struct Game {
    pub config: GameConfig,
    pub client: Client,
    pub tick_timer: Timer,
    pub bevy_caller: Arc<BevyPacketCaller>,
    pub ball: Ball,
    pub player_me: Player,
    pub actual_command: SelfCommandUpdatePacket,
    pub player_enemy: Player,
    pub start_instant: Instant,
    pub arena_entity: Entity,
}

impl Game {
    pub fn start(
        config: GameConfig,
        commands: &mut Commands,
        meshes: &mut ResMut<Assets<Mesh>>,
        materials: &mut ResMut<Assets<ColorMaterial>>,
        client: Client,
        bevy_caller: Arc<BevyPacketCaller>,
        player_me_side: PlayerSide,
        player_me_name: String,
        player_enemy_name: String,
    ) -> Self {
        println!("Starting game");
        let ball = Ball::default_of(&config, commands, meshes, materials);
        let player_me = Player::default_of(
            &config,
            player_me_name,
            player_me_side,
            commands,
            meshes,
            materials,
        );
        let player_enemy = Player::default_of(
            &config,
            player_enemy_name,
            player_me_side.opposite(),
            commands,
            meshes,
            materials,
        );

        let arena_entity = commands
            .spawn(MaterialMesh2dBundle {
                mesh: Mesh2dHandle(
                    meshes.add(Rectangle::new(config.arena.width(), config.arena.height())),
                ),
                material: materials.add(Color::srgb(0.1, 0.1, 0.1)),
                transform: Transform::from_xyz(
                    (config.arena.min.x + config.arena.max.x) / 2.0,
                    (config.arena.min.y + config.arena.max.y) / 2.0,
                    -10.0,
                ),
                ..default()
            })
            .id();

        let game = Self {
            config,
            client,
            tick_timer: Timer::from_seconds(0.05, TimerMode::Repeating),
            bevy_caller,
            ball,
            player_me,
            actual_command: SelfCommandUpdatePacket::None,
            player_enemy,
            start_instant: Instant::now(),
            arena_entity,
        };

        game
    }

    fn get_player_mut(&mut self, side: PlayerSide) -> &mut Player {
        if self.player_me.side == side {
            &mut self.player_me
        } else {
            &mut self.player_enemy
        }
    }

    fn get_player(&self, side: PlayerSide) -> &Player {
        if self.player_me.side == side {
            &self.player_me
        } else {
            &self.player_enemy
        }
    }
}

pub struct GamePlugin;

impl Plugin for GamePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, update);
        app.add_systems(PlayerPositionPacketClientSchedule, player_position_read);
        app.add_systems(BallPositionPacketClientSchedule, ball_position_read);
        app.add_systems(ClackPacketClientSchedule, clack_packet_read);
        app.add_systems(PointPacketClientSchedule, point_packet_read);
    }
}

fn update(
    mut commands: Commands,
    keyboard_input: Res<ButtonInput<KeyCode>>,
    mut query: Query<(Entity, &mut Game)>,
) {
    for (entity, mut game) in query.iter_mut() {
        let tick = game.client.tick_start();
        match tick {
            ClientTickResult::ReceivedMessage(message) => {
                let bevy_caller = Arc::clone(&game.bevy_caller);
                commands.add(move |world: &mut World| {
                    world.insert_resource(ServerPacketSchedule {
                        game_entity: entity.clone(),
                    });
                    for deserialized_packet in message.to_packet_list() {
                        bevy_caller.client_call(world, deserialized_packet);
                    }
                    world.remove_resource::<ServerPacketSchedule>().unwrap();
                });

                let new_command = {
                    if keyboard_input.pressed(KeyCode::KeyW) {
                        SelfCommandUpdatePacket::Up
                    } else if keyboard_input.pressed(KeyCode::KeyS) {
                        SelfCommandUpdatePacket::Down
                    } else {
                        SelfCommandUpdatePacket::None
                    }
                };

                if new_command != game.actual_command {
                    game.client.send_packet(&new_command);
                    game.actual_command = new_command;
                }

                game.client.tick_after_message();
            }
            ClientTickResult::Disconnected => {
                panic!(
                    "client disconnected: {:?}",
                    game.client.take_disconnect_reason().unwrap()
                )
            }
            _ => (),
        }
    }
}

fn ball_position_read(
    player_packet_schedule: Res<ServerPacketSchedule>,
    mut packet: ResMut<ClientPacketResource<BallPositionPacket>>,
    query: Query<&Game>,
    mut ball_query: Query<&mut Transform>,
) {
    let packet = packet.packet.take().unwrap();
    let game = query.get(player_packet_schedule.game_entity).unwrap();

    let mut transform = ball_query.get_mut(game.ball.entity).unwrap();
    transform.translation.x = packet.new_pos.x;
    transform.translation.y = packet.new_pos.y;
}

fn player_position_read(
    player_packet_schedule: Res<ServerPacketSchedule>,
    mut packet: ResMut<ClientPacketResource<PlayerPositionPacket>>,
    query: Query<&Game>,
    mut player_query: Query<&mut Transform>,
) {
    let packet = packet.packet.take().unwrap();
    let game = query.get(player_packet_schedule.game_entity).unwrap();

    let player = game.get_player(packet.side);
    let mut transform = player_query.get_mut(player.entity).unwrap();
    transform.translation.y = packet.new_y;
}

fn clack_packet_read(
    player_packet_schedule: Res<ServerPacketSchedule>,
    mut packet: ResMut<ClientPacketResource<ClackPacket>>,
    query: Query<&Game>,
    mut ball_query: Query<&mut Handle<ColorMaterial>>,
    mut materials: ResMut<Assets<ColorMaterial>>,
) {
    let _packet = packet.packet.take().unwrap();
    let game = query.get(player_packet_schedule.game_entity).unwrap();

    *ball_query.get_mut(game.ball.entity).unwrap() = materials.add(random_color());
}

fn point_packet_read(
    player_packet_schedule: Res<ServerPacketSchedule>,
    mut packet: ResMut<ClientPacketResource<PointPacket>>,
    mut query: Query<&mut Game>,
) {
    let packet = packet.packet.take().unwrap();
    let mut game = query.get_mut(player_packet_schedule.game_entity).unwrap();

    let player = game.get_player_mut(packet.side);
    player.points += 1;
}

fn random_color() -> Color {
    let mut rng = thread_rng();

    Color::srgb(
        rng.gen_range(0.0..1.0),
        rng.gen_range(0.0..1.0),
        rng.gen_range(0.0..1.0),
    )
}
