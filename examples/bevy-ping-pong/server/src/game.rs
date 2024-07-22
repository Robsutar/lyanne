use std::{net::SocketAddr, sync::Arc, time::Instant};

use bevy::prelude::*;
use bevy_ping_pong::{
    BevyPacketCaller, ClackPacket, ConnectionRefuseMessage, GameConfig, GameStartPacket,
    PlayerPositionPacket, PlayerSide, PointPacket, SelfCommandUpdatePacket,
    SelfCommandUpdatePacketServerSchedule,
};
use lyanne::{
    packets::{SerializedPacket, SerializedPacketList, ServerPacketResource},
    transport::server::Server,
};
use rand::{thread_rng, Rng};

pub struct Ball {
    pub radius: f32,
    pub pos: Vec2,
    pub velocity: Vec2,
}

impl Ball {
    fn default_of(config: &GameConfig) -> Self {
        let x = (config.arena.min.x + config.arena.max.x) / 2.0;
        let y = (config.arena.min.y + config.arena.max.y) / 2.0;

        let mut rng = thread_rng();
        let angle: f32 = rng.gen_range(0.0..2.0 * PI);
        let speed_distance = 10.0;
        Self {
            radius: config.ball_radius,
            pos: Vec2::new(x, y),
            velocity: Vec2::new(speed_distance * angle.cos(), speed_distance * angle.sin()),
        }
    }
}

pub struct Player {
    pub addr: SocketAddr,
    pub name: String,
    pub side: PlayerSide,
    pub points: usize,
    pub goal_x: f32,
    pub actual_command: SelfCommandUpdatePacket,
    pub pos: Vec2,
}

impl Player {
    fn default_of(config: &GameConfig, addr: SocketAddr, name: String, side: PlayerSide) -> Self {
        let x = {
            match side {
                PlayerSide::Left => config.arena.min.x,
                PlayerSide::Right => config.arena.max.x,
            }
        };
        let y = (config.arena.min.y + config.arena.max.y) / 2.0;

        Self {
            addr,
            name,
            side,
            points: 0,
            goal_x: x,
            actual_command: SelfCommandUpdatePacket::None,
            pos: Vec2::new(x, y),
        }
    }

    fn get_bar(&self, config: &GameConfig) -> Rect {
        Rect::new(
            self.pos.x - config.player_bar_size.x / 2.0,
            self.pos.y - config.player_bar_size.y / 2.0,
            self.pos.x + config.player_bar_size.x / 2.0,
            self.pos.y + config.player_bar_size.y / 2.0,
        )
    }

    fn tick_for_movement(&mut self, player_movement_speed: f32, goal_min_max_y: (f32, f32)) {
        match self.actual_command {
            SelfCommandUpdatePacket::Up => {
                if self.pos.y + player_movement_speed < goal_min_max_y.1 {
                    self.pos.y += player_movement_speed;
                }
            }
            SelfCommandUpdatePacket::Down => {
                if self.pos.y + player_movement_speed > goal_min_max_y.0 {
                    self.pos.y -= player_movement_speed;
                }
            }
            SelfCommandUpdatePacket::None => (),
        }
    }
}

#[derive(Resource)]
struct PlayerPacketSchedule {
    game_entity: Entity,
    side: PlayerSide,
}

#[derive(Component)]
pub struct Game {
    pub config: GameConfig,
    pub server: Server,
    pub tick_timer: Timer,
    pub bevy_caller: Arc<BevyPacketCaller>,
    pub ball: Ball,
    pub player_left: Player,
    pub player_right: Player,
    pub start_instant: Instant,
}

impl Game {
    pub fn start(
        config: GameConfig,
        server: Server,
        bevy_caller: Arc<BevyPacketCaller>,
        player_left_addr: SocketAddr,
        player_left_name: String,
        player_right_addr: SocketAddr,
        player_right_name: String,
    ) -> Self {
        println!("Starting game");
        let ball = Ball::default_of(&config);
        let player_left = Player::default_of(
            &config,
            player_left_addr,
            player_left_name,
            PlayerSide::Left,
        );
        let player_right = Player::default_of(
            &config,
            player_right_addr,
            player_right_name,
            PlayerSide::Right,
        );
        let game = Self {
            config,
            server,
            tick_timer: Timer::from_seconds(0.05, TimerMode::Repeating),
            bevy_caller,
            ball,
            player_left,
            player_right,
            start_instant: Instant::now(),
        };

        {
            game.server.tick_start();

            for client in game.server.connected_clients_iter() {
                let addr = client.key().clone();

                if addr == game.player_left.addr {
                    let start_packet = GameStartPacket {
                        owned_type: PlayerSide::Left,
                        enemy_name: game.player_right.name.clone(),
                        config: game.config.clone(),
                    };
                    game.server.send_packet(&client, &start_packet)
                } else if addr == game.player_right.addr {
                    let start_packet = GameStartPacket {
                        owned_type: PlayerSide::Right,
                        enemy_name: game.player_left.name.clone(),
                        config: game.config.clone(),
                    };
                    game.server.send_packet(&client, &start_packet)
                } else {
                    panic!("Invalid player connected");
                }
            }

            game.server.tick_end();
        }

        game
    }

    fn get_player_mut(&mut self, side: PlayerSide) -> &mut Player {
        match side {
            PlayerSide::Left => &mut self.player_left,
            PlayerSide::Right => &mut self.player_right,
        }
    }
}

pub struct GamePlugin;

impl Plugin for GamePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, update);
        app.add_systems(
            SelfCommandUpdatePacketServerSchedule,
            self_command_update_read,
        );
    }
}

fn update(mut commands: Commands, mut query: Query<(Entity, &mut Game)>, time: Res<Time>) {
    for (entity, mut game) in query.iter_mut() {
        if game.tick_timer.tick(time.delta()).just_finished() {
            let tick_result = game.server.tick_start();

            let clients_packets_to_process = tick_result.received_messages;
            let clients_to_auth = tick_result.to_auth;

            for (addr, _) in clients_to_auth {
                info!("refusing client {:?}", addr,);
                game.server.refuse(
                    addr,
                    SerializedPacketList::create(vec![game.server.packet_registry().serialize(
                        &ConnectionRefuseMessage {
                            message: "Match already started".to_owned(),
                        },
                    )]),
                );
            }

            for (addr, reason) in tick_result.disconnected {
                info!("client disconnected: {:?}, reason: {:?}", addr, reason);

                todo!("finish match");
            }

            for (addr, message_list) in clients_packets_to_process {
                let side = {
                    if addr == game.player_left.addr {
                        game.player_left.side
                    } else if addr == game.player_right.addr {
                        game.player_right.side
                    } else {
                        panic!("Invalid player connected");
                    }
                };
                let bevy_caller = Arc::clone(&game.bevy_caller);
                commands.add(move |world: &mut World| {
                    world.insert_resource(PlayerPacketSchedule {
                        game_entity: entity.clone(),
                        side,
                    });
                    for message in message_list {
                        for deserialized_packet in message.packets {
                            bevy_caller.server_call(world, deserialized_packet);
                        }
                    }
                    world.remove_resource::<PlayerPacketSchedule>().unwrap();
                });
            }

            let velocity = game.ball.velocity;
            game.ball.pos += velocity;

            let mut clack = false;

            if is_colliding(
                Rect::new(
                    game.player_left.goal_x,
                    game.config.goal_min_max_y.0,
                    game.player_left.goal_x,
                    game.config.goal_min_max_y.1,
                ),
                &game.ball,
            ) {
                game.player_left.points += 1;
                reset_round(&mut game);
                send_point_packets(&mut game, PlayerSide::Left);

                let ball_speed_multiplier = game.config.ball_speed_multiplier;
                game.ball.velocity *= ball_speed_multiplier;
                clack = true;
                println!("left point");
            } else if is_colliding(
                Rect::new(
                    game.player_right.goal_x,
                    game.config.goal_min_max_y.0,
                    game.player_right.goal_x,
                    game.config.goal_min_max_y.1,
                ),
                &game.ball,
            ) {
                game.player_right.points += 1;
                reset_round(&mut game);
                send_point_packets(&mut game, PlayerSide::Right);

                let ball_speed_multiplier = game.config.ball_speed_multiplier;
                game.ball.velocity *= ball_speed_multiplier;
                clack = true;
                println!("right point");
            } else if try_collide(game.player_left.get_bar(&game.config), &mut game.ball) {
                clack = true;
                println!(
                    "left collide {:?} retry? {:?}",
                    game.player_left.get_bar(&game.config),
                    is_colliding(game.player_left.get_bar(&game.config), &mut game.ball)
                );
            } else if try_collide(game.player_right.get_bar(&game.config), &mut game.ball) {
                clack = true;
                println!("right collide");
            } else if try_outside_collide(game.config.arena, &mut game.ball) {
                println!("Outside collide");
                clack = true;
            }

            let player_movement_speed = game.config.player_movement_speed;
            let goal_min_max_y = game.config.goal_min_max_y;
            game.player_left
                .tick_for_movement(player_movement_speed, goal_min_max_y);
            game.player_right
                .tick_for_movement(player_movement_speed, goal_min_max_y);

            let player_left_move_packet =
                game.server
                    .packet_registry()
                    .serialize(&PlayerPositionPacket {
                        player: game.player_left.side,
                        new_y: game.player_left.pos.y,
                    });
            let player_right_move_packet =
                game.server
                    .packet_registry()
                    .serialize(&PlayerPositionPacket {
                        player: game.player_right.side,
                        new_y: game.player_right.pos.y,
                    });

            for client in game.server.connected_clients_iter() {
                game.server.send_packet_serialized(
                    &client,
                    SerializedPacket::clone(&player_left_move_packet),
                );
                game.server.send_packet_serialized(
                    &client,
                    SerializedPacket::clone(&player_right_move_packet),
                );
            }

            if clack {
                let clack_packet = game.server.packet_registry().serialize(&ClackPacket);
                for client in game.server.connected_clients_iter() {
                    game.server
                        .send_packet_serialized(&client, SerializedPacket::clone(&clack_packet));
                }
            }

            game.server.tick_end();
        }
    }
}

fn self_command_update_read(
    player_packet_schedule: Res<PlayerPacketSchedule>,
    mut packet: ResMut<ServerPacketResource<SelfCommandUpdatePacket>>,
    mut query: Query<&mut Game>,
) {
    let packet = packet.packet.take().unwrap();
    let mut game = query.get_mut(player_packet_schedule.game_entity).unwrap();

    let player = game.get_player_mut(player_packet_schedule.side);
    player.actual_command = packet;
}

fn reset_round(game: &mut Mut<Game>) {
    let y = (game.config.arena.min.y + game.config.arena.max.y) / 2.0;
    {
        let x = (game.config.arena.min.x + game.config.arena.max.x) / 2.0;
        game.ball.pos = Vec2::new(x, y);

        let mut rng = thread_rng();
        let angle: f32 = rng.gen_range(0.0..2.0 * PI);
        let speed_distance = 10.0;
        game.ball.velocity = Vec2::new(speed_distance * angle.cos(), speed_distance * angle.sin());
    }

    game.player_left.pos.y = y;
    game.player_right.pos.y = y;
}

fn send_point_packets(game: &mut Mut<Game>, side: PlayerSide) {
    let point_packet = game
        .server
        .packet_registry()
        .serialize(&PointPacket { side });

    for client in game.server.connected_clients_iter() {
        game.server
            .send_packet_serialized(&client, SerializedPacket::clone(&point_packet));
    }
}

fn is_colliding(rect: Rect, ball: &Ball) -> bool {
    if ball.pos.x - ball.radius >= rect.min.x && ball.pos.x + ball.radius <= rect.max.x {
        if ball.pos.y - ball.radius >= rect.min.y && ball.pos.y + ball.radius <= rect.max.y {
            return true;
        }
    }
    false
}

fn try_collide(rect: Rect, ball: &mut Ball) -> bool {
    if ball.pos.x + ball.radius >= rect.min.x && ball.pos.x - ball.radius <= rect.max.x {
        if ball.pos.y - ball.radius <= rect.max.y && ball.pos.y + ball.radius >= rect.max.y {
            ball.velocity.y = ball.velocity.y.abs();
            return true;
    }
        if ball.pos.y + ball.radius >= rect.min.y && ball.pos.y - ball.radius <= rect.min.y {
        ball.velocity.y = -ball.velocity.y.abs();
            return true;
        }
    }
    if ball.pos.y + ball.radius >= rect.min.y && ball.pos.y - ball.radius <= rect.max.y {
        if ball.pos.x - ball.radius <= rect.max.x && ball.pos.x + ball.radius >= rect.max.x {
            ball.velocity.x = ball.velocity.x.abs();
            return true;
    }
        if ball.pos.x + ball.radius >= rect.min.x && ball.pos.x - ball.radius <= rect.min.x {
            ball.velocity.x = -ball.velocity.x.abs();
        return true;
    }
    }
    false
}

fn try_outside_collide(rect: Rect, ball: &mut Ball) -> bool {
    let mut collision = false;

    if ball.pos.x - ball.radius <= rect.min.x {
        ball.velocity.x = ball.velocity.x.abs();
        collision = true;
    } else if ball.pos.x + ball.radius >= rect.max.x {
        ball.velocity.x = -ball.velocity.x.abs();
        collision = true;
    }

    if ball.pos.y - ball.radius <= rect.min.y {
        ball.velocity.y = ball.velocity.y.abs();
        collision = true;
    } else if ball.pos.y + ball.radius >= rect.max.y {
        ball.velocity.y = -ball.velocity.y.abs();
        collision = true;
    }

    collision
}
