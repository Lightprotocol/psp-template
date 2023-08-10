use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;

pub mod psp_accounts;
pub use psp_accounts::*;
pub mod auto_generated_accounts;
pub use auto_generated_accounts::*;
pub mod processor;
pub use processor::*;
pub mod verifying_key;
pub use verifying_key::*;


declare_id!("{{program-id}}");

#[constant]
pub const PROGRAM_ID: &str = "{{program-id}}";

#[program]
pub mod {{rust-name}} {
    use light_verifier_sdk::light_transaction::{Amounts, Proof};

    use super::*;

    /// This instruction is the first step of a shieled transaction.
    /// It creates and initializes a verifier state account to save state of a verification during{ VERIFYINGKEY_{{VERIFYING_KEY_NAME}}.nr_pubinputs }
    /// computation verifying the zero-knowledge proof (ZKP). Additionally, it stores other data
    /// such as leaves, amounts, recipients, nullifiers, etc. to execute the protocol logic
    /// in the last transaction after successful ZKP verification. light_verifier_sdk::light_instruction::LightInstruction2
    pub fn light_instruction_first<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, LightInstructionFirst<'info, { VERIFYINGKEY_{{VERIFYING_KEY_NAME}}.nr_pubinputs }>>,
        inputs: Vec<u8>,
    ) -> Result<()> {
        let inputs_des: InstructionDataLightInstructionFirst =
            InstructionDataLightInstructionFirst::try_deserialize_unchecked(
                &mut [vec![0u8; 8], inputs].concat().as_slice(),
            )?;
        let proof = Proof {
            a: [0u8; 64],
            b: [0u8; 128],
            c: [0u8; 64],
        };
        let public_amount = Amounts {
            sol: inputs_des.public_amount_sol,
            spl: inputs_des.public_amount_spl,
        };
        let pool_type = [0u8; 32];
        let mut program_id_hash = hash(&ctx.program_id.to_bytes()).to_bytes();
        program_id_hash[0] = 0;

        let mut checked_inputs: [[u8; 32]; { VERIFYINGKEY_{{VERIFYING_KEY_NAME}}.nr_pubinputs }] = [[0u8; 32]; { VERIFYINGKEY_{{VERIFYING_KEY_NAME}}.nr_pubinputs }];
        checked_inputs[0] = program_id_hash;
        checked_inputs[1] = inputs_des.transaction_hash;

        process_psp_instruction_first::<{ VERIFYINGKEY_{{VERIFYING_KEY_NAME}}.nr_pubinputs }, 17>(
            ctx,
            &proof,
            &public_amount,
            &inputs_des.input_nullifier,
            &inputs_des.output_commitment,
            &checked_inputs,
            &inputs_des.encrypted_utxos,
            &pool_type,
            &inputs_des.root_index,
            &inputs_des.relayer_fee,
        )
    }

    pub fn light_instruction_second<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, LightInstructionSecond<'info, { VERIFYINGKEY_{{VERIFYING_KEY_NAME}}.nr_pubinputs }>>,
        inputs: Vec<u8>,
    ) -> Result<()> {
        inputs.chunks(32).enumerate().for_each(|(i, input)| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(input);
            ctx.accounts.verifier_state.checked_public_inputs[2 + i] = arr
        });
        Ok(())
    }

    /// This instruction is the third step of a shielded transaction.
    /// The proof is verified with the parameters saved in the first transaction.
    /// At successful verification protocol logic is executed.
    pub fn light_instruction_third<'a, 'b, 'c, 'info>(
        ctx: Context<'a, 'b, 'c, 'info, LightInstructionThird<'info, { VERIFYINGKEY_{{VERIFYING_KEY_NAME}}.nr_pubinputs }>>,
        inputs: Vec<u8>,
    ) -> Result<()> {
        msg!(
            "checked inputs {:?}",
            ctx.accounts.verifier_state.checked_public_inputs[2]
        );
        verify_programm_proof(&ctx, &inputs)?;
        cpi_verifier_two(&ctx, &inputs)
    }

    /// Close the verifier state to reclaim rent in case the proofdata is wrong and does not verify.
    pub fn close_verifier_state<'a, 'b, 'c, 'info>(
        _ctx: Context<'a, 'b, 'c, 'info, CloseVerifierState<'info, { VERIFYINGKEY_{{VERIFYING_KEY_NAME}}.nr_pubinputs }>>,
    ) -> Result<()> {
        Ok(())
    }
}
